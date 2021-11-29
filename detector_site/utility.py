from androguard.core.bytecodes import dvm
import re
import os
import shutil
import json
import fnmatch
import subprocess


def list_files(directory, string):
    result = []
    for dirpath, dirnames, files in os.walk(directory):
        for file in fnmatch.filter(files, string):
            result.append(os.path.join(dirpath, file))
    return result


def unzip_apk(analyze_apk):
    # directory = source_directory + os.path.basename(filename).replace('.apk', '')
    directory = analyze_apk.replace('.apk', '/')
    if not os.path.exists(directory):
        command = "java -jar apktool.jar d " + analyze_apk + " -o " + directory + " -f"

        p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        output, err = p.communicate()


def opcodes_analysis(androguard_apk):
    # http://blog.k3170makan.com/2014/11/automated-dex-decompilation-using.html
    temp = {}

    dalvik = dvm.DalvikVMFormat(androguard_apk.get_dex())
    for current_class in dalvik.get_classes():
        for method in current_class.get_methods():
            byte_code = method.get_code()
            if byte_code is not None:
                byte_code = byte_code.get_bc()
                for inst in byte_code.get_instructions():
                    inst_name = inst.get_name()
                    if inst_name not in temp:
                        temp[inst_name] = 1
                    else:
                        temp[inst_name] += 1
    return temp


def read_smali_files(smali_list, api_packages_list, api_classes_list):
    list_smali_api_calls = {}
    list_smali_strings = []
    for smali_file in smali_list:
        with open(smali_file) as f:
            content = f.readlines()
        content = [x.strip() for x in content]

        # SEARCHING STRINGS
        splitted_string = [x.split() for x in content if 'const-string' in x]
        acum = []
        for elem in splitted_string:
            elem = elem[2:]
            acum.append(' '.join(elem).replace('\"', '').strip())
        list_smali_strings.extend(acum)

        # SEARCHING FOR API CALLS
        content = [x for x in content if 'invoke-' in x or 'invoke-virtual' in x or 'invoke-direct' in x]

        for elem in content:
            # elem = elem.split('->')
            elem = re.sub("\{[^]]*\}", lambda x: x.group(0).replace(',', ''),
                          elem)  # Remove commands between brackets (invoke)

            elem = re.split(', |;->', elem)

            if len(elem) != 2:
                # TODO CHECK IF CORRECT. Class not defined, so it must came from Object, but should be checked
                try:
                    package = elem[1]
                    method = elem[2]
                except IndexError:
                    print
                    "Incorrect API calls transcription"

            else:
                package = "Object"
                method = elem[1]
            if package.startswith("L"):
                package = package[1:]

            package = package.split("/")
            _class = package[-1]
            del package[-1]
            package = '.'.join(package)
            method = method.split('(')[0]

            if package in api_packages_list and _class in api_classes_list and method != '<init>':
                pack_class = package + '.' + _class + '.' + method
                if pack_class in list_smali_api_calls:
                    list_smali_api_calls[pack_class] += 1
                else:
                    list_smali_api_calls[pack_class] = 1

    return list_smali_api_calls, list_smali_strings


def read_strings_and_apicalls(analyze_apk, api_packages_list, api_classes_list):
    unzip_apk(analyze_apk)

    smali_files_list = list_files(analyze_apk.replace('.apk', '/'), '*.smali')

    list_smali_api_calls, list_smali_strings = read_smali_files(smali_files_list, api_packages_list, api_classes_list)

    return list_smali_api_calls, list_smali_strings


def save_as_csv(data):
    with open('data.csv', 'w') as f:
        for key in data.keys():
            f.write("%s,%s\n" % (key, data[key]))
    return 0


def load_file(filename):
    with open(filename, 'rb') as text_file:
        lines = text_file.readlines()
    return lines


def cleanup(analyze_apk):
    try:
        # directory = source_directory + os.path.basename(filename).replace('.apk', '')
        directory = analyze_apk.replace('.apk', '/')
        shutil.rmtree(directory)
    except Exception as err:
        print(err)


def save_as_json(data, output_name):
    with open(str(output_name), 'w') as fp:
        json.dump(data, fp, indent=4)
    print('[*] Analysis saved into:', str(output_name))

