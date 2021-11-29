from django.shortcuts import render
from django.core.files.storage import FileSystemStorage
import collections
from detector.settings import BASE_DIR
import detector_site.utility as utility
from collections import Counter
from androguard.core.bytecodes import apk
import os
import hashlib
import json
from django.http.response import HttpResponse, HttpResponseRedirect
import json
import numpy as np
import pandas as pd
from sklearn.ensemble import AdaBoostClassifier, VotingClassifier
from sklearn.svm import SVC
from sklearn.tree import DecisionTreeClassifier
# from sklearn.externals import joblib
import joblib

def home(request):
    if os.path.exists(os.path.join(BASE_DIR,'data1.json')):
        os.remove(os.path.join(BASE_DIR,'data1.json'))
    if os.path.exists(os.path.join(BASE_DIR,'media\\malware\\app.apk')):
        os.remove(os.path.join(BASE_DIR,'media\\malware\\app.apk'))
    return render(request,'home.html')

def upload(request):
    if request.method == 'POST' and request.FILES.getlist('myfile'):
        myfile = request.FILES.getlist('myfile')
        fs = FileSystemStorage()
        i=1
        for f in myfile:
          fs.save('malware/app.apk', f)
          i+=1
        preprocessing()
        app_type,mal = final_testing()
        
        with open('data1.json', 'r') as jsonFile:
            data = json.load(jsonFile)
        for datarow in data:
            permission = datarow['Permissions']
            opcodes = datarow['Opcodes']
            break
        lenp=len(permission)
        leno=len(opcodes)
    return render(request,'result.html',{'type':mal,'app_type':app_type,'permissions':permission,'no_of_permissions':lenp,'opcodes':opcodes,'no_of_opcodes':leno}) 

def result(request):
    with open('data1.json', 'r') as jsonFile:
        data = json.load(jsonFile)
    for datarow in data:
        permission = datarow['Permissions']
        opcodes = datarow['Opcodes']
    # print(opcodes)
    lenp=len(permission)
    leno=len(opcodes)
    return render(request,'result.html',{'type':True,'app_type':'Malware','permissions':permission,'no_of_permissions':lenp,'opcodes':opcodes,'no_of_opcodes':leno})
    # return HttpResponse('hello')

def preprocessing():
    def extract_features(apkname):
        # apkname = 'DEMO.apk'
        androguard_apk_object = None

        static_analysis_dict = collections.OrderedDict()
        try:
            androguard_apk_object = apk.APK(apkname)
            hasher_sha1 = hashlib.sha1()

            with open(apkname, 'rb') as afile:
                buf = afile.read()
                hasher_sha1.update(buf)

            sha1 = hasher_sha1.hexdigest()
            static_analysis_dict["sha1"] = sha1
        except Exception as err:
            print("ERROR in APK: " + str(err))
            return None

        # Package name
        static_analysis_dict['Package name'] = androguard_apk_object.get_package()

        # Permissions
        static_analysis_dict['Permissions'] = androguard_apk_object.get_permissions()

        # Opcodes
        static_analysis_dict['Opcodes'] = utility.opcodes_analysis(androguard_apk_object)
        static_analysis_dict['VersionCode'] = int(androguard_apk_object.get_androidversion_code())


        API_PACKAGES_LIST = []
        API_CLASSES_LIST = []

        package_file = utility.load_file(str('info/package_index.txt'))
        API_PACKAGES_LIST = [x.strip() for x in package_file]

        class_file = utility.load_file(str('info/class_index.txt'))
        API_CLASSES_LIST = [x.strip() for x in class_file]

        list_smali_api_calls, list_smali_strings = utility.read_strings_and_apicalls(apkname, API_PACKAGES_LIST,
                                                                                    API_CLASSES_LIST)

        for api_call in list_smali_api_calls.keys():
            new_api_call = '.'.join(api_call.split(".")[:-1])
            if new_api_call in list_smali_api_calls.keys():
                list_smali_api_calls[new_api_call] = list_smali_api_calls[new_api_call] + list_smali_api_calls[api_call]
            else:
                list_smali_api_calls[new_api_call] = list_smali_api_calls[api_call]
                del list_smali_api_calls[api_call]

        static_analysis_dict['API calls'] = list_smali_api_calls
        static_analysis_dict['Strings'] = Counter(filter(None, list_smali_strings))

        # print(static_analysis_dict)

        #appending virustotal features
        # vt_apk_path = apkname.replace(DATASET_PATH, 'VT_ANALYSIS')
        # vt_apk_path = vt_apk_path.replace('.apk', '.json')

        # if os.path.exists(vt_apk_path):
        #     jsonFeatures = json.load(open(vt_apk_path))

        #     #appedning virus info
        #     for scanInfo in jsonFeatures['scans']:
        #         static_analysis_dict[str(scanInfo)] = jsonFeatures['scans'][str(scanInfo)]['detected']

        #     static_analysis_dict['vt_total'] = jsonFeatures['total']
        #     static_analysis_dict['vt_positives'] = jsonFeatures['positives']
        # else:
        #     print(str(vt_apk_path) + ' path not found' )


        return static_analysis_dict
        # dynamic


    DATASET_PATH = os.path.join(BASE_DIR,'media')
    jsonArr = list()

    def extract_data(folderpath, apkpath):
        print('processing..->' + apkpath)
        jsondata = extract_features(os.path.join(folderpath, apkpath))
        if(jsondata == None):
            return None
        if classname == 'malware':
            jsondata['malware'] = True
        else:
            jsondata['malware'] = False
        utility.cleanup(os.path.join(folderpath, apkpath))
        # print(os.path.join(folderpath, apkpath))
        return jsondata


    for classname in os.listdir(DATASET_PATH):
        # print(classname)
        folderpath = os.path.join(DATASET_PATH, classname)
        for apkfilepath in os.listdir(folderpath):
            # print('processing..->' + apkfilepath)
            # jsondata = extract_features(os.path.join(folderpath, apkfilepath))
            # if classname == 'malware':
            #     jsondata['malware'] = True
            # else:
            #     jsondata['malware'] = False
            #
            # utility.cleanup(apkfilepath)
            try:
                final = os.path.join(folderpath, apkfilepath)
                final = final.replace('.apk','/')
                if not os.path.exists(final):
                    os.mkdir(final)
                jsondata = extract_data(folderpath, apkfilepath)
                if jsondata != None:
                    jsonArr.append(jsondata)
                    print('No Exception')
            except Exception as err:
                print(err)


    utility.save_as_json(jsonArr, 'data1.json')

def final_testing():

    # ALL_PERMISSIONS = open('permissions.txt', 'r').readlines()
    # ALL_OPECODES_1 = open('opcodes.txt','r').readlines()
    # ALL_OPECODES=[]
    # ALL_STRINGS=[]
    # for x in range(len(ALL_OPECODES_1)):
    #     ALL_OPECODES.append(ALL_OPECODES_1[x].strip())

    def get_permission_matrix(permissions):
        # print(str(datarow['Package name']))
        perm_vector = np.zeros(len(ALL_PERMISSIONS))
        # print(perm_vector.shape)
        for permission in permissions:
            for i in range(len(perm_vector)):
                if ALL_PERMISSIONS[i].strip() == permission:
                    # print(ALL_PERMISSIONS[i])
                    # print('Got permission')
                    perm_vector[i] = 1
                else:
                    perm_vector[i] = 0

        # print(perm_vector)
        return perm_vector

    def generate_opcode_vector(dictOpCodes,ALL_OPECODES):
        # print(str(datarow['Package name']))
        opcode_vec = []
        # print(perm_vector.shape)
        for op in ALL_OPECODES:
            try:
                opcode_vec.append(dictOpCodes[op])
            except Exception as err:
                opcode_vec.append(0)
                # print(err)

        # print(opcode_vec)
        return opcode_vec


    # def generate_opcode_vector(dictOpCodes, ALL_OPECODES):
    #     opcode_vec = []
    #     for opcode in ALL_OPECODES:
    #         try:
    #             opcode_vec.append(dictOpCodes[opcode])
    #         except Exception as err:
    #             opcode_vec.append(0)
    #             # print(err)
    # #     return opcode_vec


    def generate_opstrings_vector(dictOpStrings, ALL_STRINGS):
        opstring_vec = []
        for opstring in ALL_STRINGS:
            try:
                opstring_vec.append(dictOpStrings[opstring])
            except Exception as err:
                opstring_vec.append(0)
                # print(err)
        return opstring_vec
    
    # =======================================================
    # =======================================================
    # =======================================================

    # with open('data.json', 'r') as jsonFile:
    #     data = json.load(jsonFile)

    # # generating all opcodes
    # # for datarow in data:
    # #     ALL_OPECODES += list(datarow['Opcodes'].keys())
    # # # print(len(ALL_OPECODES))

    # # ALL_OPECODES = sorted(list(set(ALL_OPECODES)))
    # # print('TOTAL OPCODES ' + str(len(ALL_OPECODES)))
    # # print(ALL_OPECODES)
    # # genrating all strings
    # for datarow in data:
    #     ALL_STRINGS += list(datarow['Strings'].keys())
    #     # print(len(ALL_STRINGS))

    # ALL_STRINGS = sorted(list(set(ALL_STRINGS)))
    # # print('TOTAL ALL_STRINGS ' + str(len(ALL_STRINGS)))

    # pdArr = []
    # scan_columns = []
    # appendCols = True
    # for i in range(len(data)):
    #     datarow = data[i]
    #     permission_vec = get_permission_matrix(datarow['Permissions'])
    #     # print(permission_vec)
    #     opcode_vec = generate_opcode_vector(datarow['Opcodes'],ALL_OPECODES)
    #     # print(opcode_vec)
    #     opstring_vec = generate_opstrings_vector(datarow['Strings'], ALL_STRINGS)
    #     # print(opstring_vec)

    #     dictVector = {}
    #     dictVector['Permissions'] = permission_vec
    #     dictVector['Opcodes'] = opcode_vec
    #     dictVector['Strings'] = opstring_vec
    #     dictVector['VersionCode'] = datarow['VersionCode']
    #     dictVector['isMalware'] = int(datarow['malware'])
    #     dictVector['sha1'] = str(datarow['sha1'])

    #     # vt_json = json.load(open('VT_ANALYSIS/test.json'))  # to append key value

    #     # try:
    #     #     #appedning virus info
    #     #     for scanInfo in vt_json['scans']:
    #     #         dictVector[str(scanInfo)] = int(datarow[scanInfo])
    #     #         if appendCols: scan_columns.append(str(scanInfo))

    #     #     dictVector['vt_total'] = datarow['vt_total']
    #     #     dictVector['vt_positives'] = datarow['vt_positives']
    #     # except Exception as err:
    #     #     #appedning virus info for not available
    #     #     for scanInfo in vt_json['scans']:
    #     #         dictVector[str(scanInfo)] = int(datarow['malware'])

    #     #     dictVector['vt_total'] = 0
    #     #     dictVector['vt_positives'] = 0
    #     #     print(err)

    #     appendCols = False
    #     pdArr.append(dictVector)

    #     scan_columns.append('Permissions')
    #     scan_columns.append('Opcodes')
    #     scan_columns.append('Strings')
    #     scan_columns.append('VersionCode')
    #     # scan_columns.append('vt_total')
    #     # scan_columns.append('vt_positives')
    #     scan_columns.append('isMalware')

    # df = pd.DataFrame(pdArr, columns=list(set(scan_columns)), dtype=np.float32)
    # # print(df.head())

    # # df.to_csv('dataframe.csv', index=None, header=True)

    # y = np.asarray(list(df['isMalware']))
    # del df['isMalware']


    # Xp = np.asarray(list(df['Permissions']))
    # # print(len(Xp[0]))
    # Xo = np.asarray(list(df['Opcodes']))
    # # print(len(Xo[0]))
    # Xs = np.asarray(list(df['Strings']))
    # # print(len(Xs[0]))

    # # X = [Xp + Xo + Xs]
    # X = np.concatenate((Xp, Xo), 1)
    # X = np.concatenate((X, Xs), 1)

    # del df['Permissions'], df['Opcodes'], df['Strings']

    # # print(len(df.values))
    # X = np.concatenate((X, df.values), 1)
    # # print(X[0].shape)
    # from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score

    # xTrain, xTest, yTrain, yTest = train_test_split(X, y, test_size=0.2, random_state=0, shuffle=True)
    # # print('x')

    # mlp = SVC(C=1.0, kernel='linear', probability=True, gamma=0.1, tol=0.001)
    # # print('y')
    # mlp.fit(xTrain, yTrain)
    # # print('z')
    # clf = AdaBoostClassifier(n_estimators=100, random_state=0)
    # # print('a')
    # clf.fit(xTrain, yTrain)
    # # print('b')


    # rclf = DecisionTreeClassifier(max_depth=20, random_state=0)
    # # print('c')
    # rclf.fit(xTrain, yTrain)
    # # print('d')

    # eclf2 = VotingClassifier(estimators=[('svc', mlp), ('adaboost', clf), ('rf', rclf)], voting='soft')
    # # print('e')
    # eclf2.fit(X, y)
    # print('done')

    # -------------------------------------------------------------------------
    # -------------------------------------------------------------------------
    # -------------------------------------------------------------------------

    ALL_PERMISSIONS = open('permissions.txt', 'r').readlines()
    ALL_OPECODES_1 = open('opcodes.txt','r').readlines()
    ALL_OPECODES=[]
    for x in range(len(ALL_OPECODES_1)):
        ALL_OPECODES.append(ALL_OPECODES_1[x].strip())
    # ALL_OPECODES_1=[]
    ALL_STRINGS = []
    df=[]
    X=[]
    data=""
    with open('data1.json', 'r') as jsonFile:
        data = json.load(jsonFile)

    # generating all opcodes
    # for datarow in data:
    #     ALL_OPECODES += list(datarow['Opcodes'].keys())
        # print(datarow['Opcodes'].keys())
    # print(len(ALL_OPECODES))

    # ALL_OPECODES = sorted(list(set(ALL_OPECODES)))
    # print('TOTAL OPCODES ' + str(len(ALL_OPECODES_1)))
    # print(ALL_OPECODES)
    # for op in ALL_OPECODES_1:
    #     if op in ALL_OPECODES:
    #         ALL_OPCODES.append(op)
    # ALL_OPCODES = sorted(list(set(ALL_OPCODES)))
    # print('TOTAL OPCODES ' + str(len(ALL_OPCODES)))
    # ALL_OPECODES = ALL_OPCODES.copy()
    # genrating all strings
    for datarow in data:
        ALL_STRINGS += list(datarow['Strings'].keys())
        # print(len(ALL_STRINGS))

    ALL_STRINGS = sorted(list(set(ALL_STRINGS)))
    # print('TOTAL ALL_STRINGS ' + str(len(ALL_STRINGS)))

    pdArr = []
    scan_columns = []
    appendCols = True
    for i in range(len(data)):
        datarow = data[i]
        permission_vec = get_permission_matrix(datarow['Permissions'])
        # print(len(permission_vec))
        opcode_vec = generate_opcode_vector(datarow['Opcodes'],ALL_OPECODES)
        # print(len(opcode_vec))
        opstring_vec = generate_opstrings_vector(datarow['Strings'], ALL_STRINGS)
        # print(len(opstring_vec))

        dictVector = {}
        dictVector['Permissions'] = permission_vec
        dictVector['Opcodes'] = opcode_vec
        dictVector['Strings'] = opstring_vec
        dictVector['VersionCode'] = datarow['VersionCode']
        dictVector['isMalware'] = int(datarow['malware'])
        dictVector['sha1'] = str(datarow['sha1'])

        # vt_json = json.load(open('VT_ANALYSIS/test.json'))  # to append key value

        # try:
        #     #appedning virus info
        #     for scanInfo in vt_json['scans']:
        #         dictVector[str(scanInfo)] = int(datarow[scanInfo])
        #         if appendCols: scan_columns.append(str(scanInfo))

        #     dictVector['vt_total'] = datarow['vt_total']
        #     dictVector['vt_positives'] = datarow['vt_positives']
        # except Exception as err:
        #     #appedning virus info for not available
        #     for scanInfo in vt_json['scans']:
        #         dictVector[str(scanInfo)] = int(datarow['malware'])

        #     dictVector['vt_total'] = 0
        #     dictVector['vt_positives'] = 0
        #     print(err)

        appendCols = False
        pdArr.append(dictVector)

        scan_columns.append('Permissions')
        scan_columns.append('Opcodes')
        scan_columns.append('Strings')
        scan_columns.append('VersionCode')
        # scan_columns.append('vt_total')
        # scan_columns.append('vt_positives')
        scan_columns.append('isMalware')

    df = pd.DataFrame(pdArr, columns=list(set(scan_columns)), dtype=np.float32)
    # print(df.head())

    # df.to_csv('dataframe.csv', index=None, header=True)

    y = np.asarray(list(df['isMalware']))
    del df['isMalware']


    Xp = np.asarray(list(df['Permissions']))
    # print(len(Xp[0]))
    Xo = np.asarray(list(df['Opcodes']))
    # print(len(Xo[0]))
    Xs = np.asarray(list(df['Strings']))
    # print(len(Xs[0]))

    # X = [Xp + Xo + Xs]
    X = np.concatenate((Xp, Xo), 1)
    X = np.concatenate((X, Xs), 1)

    del df['Permissions'], df['Opcodes'], df['Strings']

    # print(len(df.values))
    X = np.concatenate((X, df.values), 1)
    # print(X[4].shape)

    # pickle.dump(clf, open('clf.sav', 'wb'))
    # pickle.dump(rclf, open('rclf.sav', 'wb'))
    # pickle.dump(mlp, open('mlp.sav', 'wb'))
    clf = joblib.load(os.path.join(BASE_DIR,'detector_site\\clf.sav'))
    rclf=joblib.load(os.path.join(BASE_DIR,'detector_site\\rclf.sav'))
    mlp=joblib.load(os.path.join(BASE_DIR,'detector_site\\mlp.sav'))
    eclf2=joblib.load(os.path.join(BASE_DIR,'detector_site\\eclf2.sav'))
    y_pred = mlp.predict(X)
    y_p = clf.predict(X)
    y_p1 = rclf.predict(X)
    y_final = eclf2.predict(X)
    app_type=""
    mal = False
    if y_pred[0]==1 or y_p[0]==1 or y_p1[0]==1 or y_final[0]==1:
        app_type = "Malware"
        mal = True
    else:
        app_type = "Benign"
    return app_type, mal