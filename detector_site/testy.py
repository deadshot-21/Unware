import json
import numpy as np
import pandas as pd
from sklearn.ensemble import AdaBoostClassifier, VotingClassifier
from sklearn.svm import SVC
from sklearn.tree import DecisionTreeClassifier
import pickle
import joblib
# ALL_PERMISSIONS = open('../permissions.txt', 'r').readlines()
# ALL_OPECODES_1 = open('../opcodes.txt','r').readlines()
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

# with open('../data.json', 'r') as jsonFile:
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

ALL_PERMISSIONS = open('../permissions.txt', 'r').readlines()
ALL_OPECODES_1 = open('../opcodes.txt','r').readlines()
ALL_OPECODES=[]
for x in range(len(ALL_OPECODES_1)):
    ALL_OPECODES.append(ALL_OPECODES_1[x].strip())
# ALL_OPECODES_1=[]
ALL_STRINGS = []
df=[]
X=[]
data=""
with open('../data1.json', 'r') as jsonFile:
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
    # print(permission_vec)
    opcode_vec = generate_opcode_vector(datarow['Opcodes'],ALL_OPECODES)
    # print(len(opcode_vec))
    opstring_vec = generate_opstrings_vector(datarow['Strings'], ALL_STRINGS)
    # print(opstring_vec)

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

clf = joblib.load('./clf.sav')
rclf=joblib.load('./rclf.sav')
mlp=joblib.load('./mlp.sav')
eclf2=joblib.load('./eclf2.sav')

    # pickle.dump(clf, open('clf.sav', 'wb'))
    # pickle.dump(rclf, open('rclf.sav', 'wb'))
    # pickle.dump(mlp, open('mlp.sav', 'wb'))
y_pred = mlp.predict(X)
y_p = clf.predict(X)
y_p1 = rclf.predict(X)
y_final = eclf2.predict(X)
print(y_pred)
print(y_p)
print(y_p1)
print(y_final)
# print(y)