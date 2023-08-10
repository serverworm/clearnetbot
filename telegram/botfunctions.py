import sys

sys.path.append(".")
from vt import Virustotal

vtapi = Virustotal()


def uploadfile(file):
    hash = vtapi.upload_file(file)
    return hash


def counttests(obj):
    dcount = 0
    ucount = 0
    ncount = 0
    detected = []
    undetected = []
    notsupported = []
    dresult = []

    for ele in obj.results:
        if ele.category == "malicious":
            dcount += 1
            detected.append(ele.engine_name)
            dresult.append(ele.result)

        elif ele.category == "undetected":
            ucount += 1
            undetected.append(ele.engine_name)

        else:
            ncount += 1
            notsupported.append(ele.engine_name)

    return dcount, ucount, ncount, detected, undetected, notsupported, dresult


def cleaninfo(hash):
    obj = vtapi.file_info(hash)
    if obj == None:
        print("File does not Exist")
        return None, None, None, None

    D, U, N, DL, UL, NL, DR = counttests(obj)

    fronttext = f'📍 **Обнаружения**: __{D} / {D + U}__\
        \n\n🔖 **Имя файла**: __{obj.filename}__\
        \n🔒 **Формат файла**: __{obj.type_description} ({obj.file_type_info["file_type"]})__\
        \n📁 **Размер файла**: __{pow(2, -20) * obj.size:.2f} MB__\
        \n\n🔬 **Первый и последний анализ**:\n• __{obj.first_submission_date}__\
        \n• __{obj.last_modification_date}__\
        \n\n📰 **Описание файла**:\n• __{obj.magic}__'
    # \n\n⚜️ [Link to VirusTotal](https://virustotal.com/gui/file/{hash})'

    testtext = '**❌ - Злонамеренный\n✅ - Безопасный\n⚠️ -  Не поддерживается**\n\n➖➖➖➖➖➖➖➖➖➖\n'
    for ele in DL:
        testtext = f'{testtext}❌ {ele}\n'
    for ele in UL:
        testtext = f'{testtext}✅ {ele}\n'
    for ele in NL:
        testtext = f'{testtext}⚠️ {ele}\n'

    signatures = '🤔 Стоит задуматься.\n\n'
    for i in range(len(DR)):
        signatures = f'{signatures}❌ {DL[i]}\
    \n╰ {DR[i]}\n'

    if D == 0:
        signatures = "✅ Этот файл безопасен, \nно не забывай, что файлы внутри архива проверять стоит по отдельности."

    link = f'https://virustotal.com/gui/file/{hash}'
    return fronttext, testtext, signatures, link
