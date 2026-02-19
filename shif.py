import asyncio
import base64
import hashlib
import html
import hmac
import os
import secrets

from aiogram import Bot, Dispatcher, F
from aiogram.filters import Command
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.types import KeyboardButton, Message, ReplyKeyboardMarkup


class CipherStates(StatesGroup):
    waiting_encrypt_text = State()
    waiting_decrypt_text = State()


# Секрет бота для собственного формата шифрования.
# Можно заменить на свою длинную фразу.
SECRET_KEY = b"shifrbot-private-key-v1"
CIPHER_PREFIX = "SHIFR1."
NONCE_SIZE = 8
MAC_SIZE = 8


def _normalize_b64_padding(data: str) -> str:
    return data + "=" * ((4 - len(data) % 4) % 4)


def encrypt_text(text: str) -> str:
    raw = text.encode("utf-8")
    nonce = secrets.token_bytes(NONCE_SIZE)
    key = hashlib.sha256(SECRET_KEY + nonce).digest()

    encrypted = bytearray()
    for i, byte in enumerate(raw):
        mask = key[i % len(key)] ^ ((i * 31 + 17) & 0xFF)
        encrypted.append(byte ^ mask)

    payload = bytes(nonce) + bytes(encrypted)
    mac = hmac.new(SECRET_KEY, payload, hashlib.sha256).digest()[:MAC_SIZE]
    packed = payload + mac

    token = base64.urlsafe_b64encode(packed).decode("ascii").rstrip("=")
    return CIPHER_PREFIX + token


def decrypt_text(token: str) -> str:
    if not token.startswith(CIPHER_PREFIX):
        raise ValueError("Неизвестный формат шифра.")

    body = token[len(CIPHER_PREFIX) :]
    try:
        packed = base64.urlsafe_b64decode(_normalize_b64_padding(body))
    except Exception as exc:
        raise ValueError("Текст поврежден или формат неверный.") from exc

    if len(packed) < NONCE_SIZE + MAC_SIZE:
        raise ValueError("Слишком короткий шифр.")

    payload = packed[:-MAC_SIZE]
    got_mac = packed[-MAC_SIZE:]
    expected_mac = hmac.new(SECRET_KEY, payload, hashlib.sha256).digest()[:MAC_SIZE]
    if not hmac.compare_digest(got_mac, expected_mac):
        raise ValueError("Проверка не пройдена: это не шифр этого бота.")

    nonce = payload[:NONCE_SIZE]
    encrypted = payload[NONCE_SIZE:]
    key = hashlib.sha256(SECRET_KEY + nonce).digest()

    raw = bytearray()
    for i, byte in enumerate(encrypted):
        mask = key[i % len(key)] ^ ((i * 31 + 17) & 0xFF)
        raw.append(byte ^ mask)

    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Не удалось расшифровать текст.") from exc


main_keyboard = ReplyKeyboardMarkup(
    keyboard=[
        [KeyboardButton(text="🔐 Зашифровать"), KeyboardButton(text="🔓 Расшифровать")],
    ],
    resize_keyboard=True,
)

cancel_keyboard = ReplyKeyboardMarkup(
    keyboard=[[KeyboardButton(text="❌ Отмена")]],
    resize_keyboard=True,
)


async def cmd_start(message: Message, state: FSMContext) -> None:
    await state.clear()
    await message.answer(
        "Привет! Я бот для шифрования.\n"
        "Выбери действие кнопками ниже.",
        reply_markup=main_keyboard,
    )


async def cmd_cancel(message: Message, state: FSMContext) -> None:
    await state.clear()
    await message.answer("Действие отменено.", reply_markup=main_keyboard)


async def choose_encrypt(message: Message, state: FSMContext) -> None:
    await state.set_state(CipherStates.waiting_encrypt_text)
    await message.answer(
        "Отправь текст, который нужно зашифровать.",
        reply_markup=cancel_keyboard,
    )


async def choose_decrypt(message: Message, state: FSMContext) -> None:
    await state.set_state(CipherStates.waiting_decrypt_text)
    await message.answer(
        "Отправь шифр для расшифровки.",
        reply_markup=cancel_keyboard,
    )


async def handle_encrypt(message: Message, state: FSMContext) -> None:
    text = (message.text or "").strip()
    if not text:
        await message.answer("Пустой текст. Попробуй еще раз.")
        return

    encrypted = encrypt_text(text)
    await state.clear()
    await message.answer(
        "Готово. Твой шифр:\n\n"
        f"<code>{html.escape(encrypted)}</code>",
        parse_mode="HTML",
        reply_markup=main_keyboard,
    )


async def handle_decrypt(message: Message, state: FSMContext) -> None:
    token = (message.text or "").strip()
    if not token:
        await message.answer("Пустой шифр. Попробуй еще раз.")
        return

    try:
        decrypted = decrypt_text(token)
    except ValueError as exc:
        await message.answer(f"Ошибка: {exc}")
        return

    await state.clear()
    await message.answer(
        "Расшифровка:\n\n"
        f"<code>{html.escape(decrypted)}</code>",
        parse_mode="HTML",
        reply_markup=main_keyboard,
    )


async def fallback_message(message: Message) -> None:
    await message.answer(
        "Используй кнопки:\n"
        "🔐 Зашифровать или 🔓 Расшифровать.",
        reply_markup=main_keyboard,
    )


async def main() -> None:
    token = os.getenv("BOT_TOKEN")
    if not token:
        raise RuntimeError("Укажи токен бота в переменной окружения BOT_TOKEN.")

    bot = Bot(token=token)
    dp = Dispatcher()

    dp.message.register(cmd_start, Command("start"))
    dp.message.register(cmd_cancel, Command("cancel"))
    dp.message.register(cmd_cancel, F.text == "❌ Отмена")

    dp.message.register(choose_encrypt, F.text == "🔐 Зашифровать")
    dp.message.register(choose_decrypt, F.text == "🔓 Расшифровать")

    dp.message.register(handle_encrypt, CipherStates.waiting_encrypt_text)
    dp.message.register(handle_decrypt, CipherStates.waiting_decrypt_text)

    dp.message.register(fallback_message)

    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
