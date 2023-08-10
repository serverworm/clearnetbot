from pyrogram import Client, filters
from pyrogram.types import InlineKeyboardMarkup, InlineKeyboardButton
import pyrogram
import os
import botfunctions
import threading
import time
from telegraph import Telegraph

# bot
bot_token = os.environ.get("TOKEN", "6433236474:AAEqx-aUzHq2yQKtBgc08gU3lfDyP8dloho")
api_hash = os.environ.get("HASH", "608f11694b2ba722a53561faa7f3444f")
api_id = os.environ.get("ID", 12064443)
app = Client("my_bot", api_id=api_id, api_hash=api_hash, bot_token=bot_token)
MAXSIZE = 681574400
telegraph = Telegraph()
telegraph.create_account(short_name='VirusTotal')


# start command
@app.on_message(filters.command(["start"]))
def strt(client: pyrogram.client.Client, message: pyrogram.types.messages_and_media.message.Message):
    START = f'☀ **Привет {message.from_user.mention}! С помощью бота вы можете осуществлять анализ подозрительных файлов на предмет выявления вредоносных программ.**\
    \
\
    \n\n🔹 Вы можете отправить мне любой файл или переслать его с другого чата, а я проверю файл через 70 различных антивирусов и предоставлю подробный анализ.\
\
    \n\n🔹 Вы также можете добавить меня в свои чаты, и я смогу анализировать файлы, которые отправляют участники.\n\n\n✨ **Проект @forgotten_server**'

    app.send_message(message.chat.id, START, reply_to_message_id=message.id, disable_web_page_preview=True,
                     reply_markup=InlineKeyboardMarkup([[
                         InlineKeyboardButton("🧐 Добавить меня в чат", url="https://t.me/antiwormbot?startgroup=true")
                     ]]))


# status updater
def downstatus(statusfile, message):
    while True:
        if os.path.exists(statusfile):
            break
    while os.path.exists(statusfile):
        with open(statusfile, "r") as upread:
            txt = upread.read()
        try:
            app.edit_message_text(message.chat.id, message.id, f"🔽 Загрузка файла... {txt}")
            time.sleep(1)
        except:
            time.sleep(5)


# progress function
def progress(current, total, message):
    with open(f'{message.id}downstatus.txt', "w") as fileup:
        fileup.write(f"{current * 100 / total:.1f}%")


# check function
def checkvirus(message):
    msg = app.send_message(message.chat.id, '🔽 Загрузка файла... ', reply_to_message_id=message.id)
    print(f"Downloading: ID:  {message.id}  size: {message.document.file_size}")
    dnsta = threading.Thread(target=lambda: downstatus(f'{message.id}downstatus.txt', msg), daemon=True)
    dnsta.start()

    file = app.download_media(message, progress=progress, progress_args=[message])
    os.remove(f'{message.id}downstatus.txt')
    app.edit_message_text(message.chat.id, msg.id, '🔼 Запуск антивирусов...')
    print(f"Uploading: ID: {message.id}  size: {message.document.file_size}")

    hash = botfunctions.uploadfile(file)
    os.remove(file)
    print(f'ID: {message.id}  HASH: {hash}')

    if hash == 0:
        app.edit_message_text(message.chat.id, msg.id, "✖️ Ошибка")
        print("HASH is 0")
        return

    app.edit_message_text(message.chat.id, msg.id, '⚙️ Анализ файла... ')
    print(f"Checking: ID:  {message.id}  size: {message.document.file_size}")
    maintext, checktext, signatures, link = botfunctions.cleaninfo(hash)

    if maintext == None:
        app.edit_message_text(message.chat.id, msg.id, "✖️ Ошибка")
        print("Function returned None")
        return

    response = telegraph.create_page('VT', content=[f'{maintext}-|-{checktext}-|-{signatures}-|-{link}'])
    tlink = response['url']

    app.edit_message_text(message.chat.id, msg.id, maintext,
                          reply_markup=InlineKeyboardMarkup([[
                              InlineKeyboardButton("🏴‍☠️ Обнаружения", callback_data=f"D|{tlink}"),
                              InlineKeyboardButton("🤔 Вердикт", callback_data=f"S|{tlink}"),
                          ],
                              [
                                  InlineKeyboardButton("🔗 Отчёт на VirusTotal", url=link)
                              ]]))


# document
@app.on_message(filters.document)
def docu(client: pyrogram.client.Client, message: pyrogram.types.messages_and_media.message.Message):
    if int(message.document.file_size) > MAXSIZE:
        app.send_message(message.chat.id, "⭕️ Файл слишком велик, он не должен быть более 650 MB",
                         reply_to_message_id=message.id)
        return
    vt = threading.Thread(target=lambda: checkvirus(message), daemon=True)
    vt.start()


# call back functon
@app.on_callback_query()
def callbck(client: pyrogram.client.Client, message: pyrogram.types.CallbackQuery):
    url = message.message.reply_markup.inline_keyboard[1][0].url
    datas = message.data.split("|")
    action = datas[0]
    tlink = datas[1]
    res = telegraph.get_page(tlink.split("https://telegra.ph/")[1], return_content=True, return_html=False)
    result = res["content"][0].split("-|-")
    maintext = result[0]
    checktext = result[1]
    signatures = result[2]

    if action == "B":
        app.edit_message_text(message.message.chat.id, message.message.id, maintext,
                              reply_markup=InlineKeyboardMarkup([[
                                  InlineKeyboardButton("🏴‍☠️ Обнаружения", callback_data=f"D|{tlink}"),
                                  InlineKeyboardButton("🤔 Вердикт", callback_data=f"S|{tlink}")
                              ],
                                  [
                                      InlineKeyboardButton("🔗 Отчёт на VirusTotal", url=url)
                                  ]]))

    if action == "D":
        app.edit_message_text(message.message.chat.id, message.message.id, checktext,
                              reply_markup=InlineKeyboardMarkup([[
                                  InlineKeyboardButton("🔙 Назад", callback_data=f"B|{tlink}"),
                                  InlineKeyboardButton("🤔 Вердикт", callback_data=f"S|{tlink}"),
                              ],
                                  [
                                      InlineKeyboardButton("🔗 Отчёт на VirusTotal", url=url)
                                  ]]))

    if action == "S":
        app.edit_message_text(message.message.chat.id, message.message.id, signatures,
                              reply_markup=InlineKeyboardMarkup([[
                                  InlineKeyboardButton("🔙 Назад", callback_data=f"B|{tlink}"),
                                  InlineKeyboardButton("‍🏴‍☠️ Обнаружения", callback_data=f"D|{tlink}")
                              ],
                                  [
                                      InlineKeyboardButton("🔗 Отчёт на VirusTotal", url=url)
                                  ]]))


app.run()
