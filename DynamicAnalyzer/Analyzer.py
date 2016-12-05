# -*- coding: utf_8 -*-
from xml.dom import minidom
from .dvm_permissions import DVM_PERMISSIONS
import os,platform,subprocess,time,zipfile

# sospende il processo per alcuni secondi		
def Wait(sec):
	print "\n[INFO] Waiting for " + str(sec) + " seconds..."
	time.sleep(sec)

# formatta correttamente la lista dei permessi		
def FormatPermissions(PERMISSIONS):
    try:
        print "\n[INFO] Formatting Permissions"
        DESC = ''
        for permission in PERMISSIONS:
            DESC = DESC + '<tr><td>' + permission + '</td>'
            for l in PERMISSIONS[permission]:
                DESC = DESC + '<td>' + l + '</td>'
            DESC = DESC+ '</tr>'
        DESC = DESC.replace('normal','<span style="color:#0000FF">normal</span>').replace('dangerous','<span style="color:#FF0000">dangerous</span>').replace('signature','<span style="color:#FF6633">signature</span>').replace('signatureOrSystem','<span style="color:#8A00E6">SignatureOrSystem</span>')
        return DESC
    except:
		print "\n[ERROR] Formatting Permissions"
		return PERMISSIONS

# formatta correttamente il risultato della valutazione del classificatore		
def FormatEvaluation(EVALUATION):
	try:
		print "\n[INFO] Formatting Evaluation Results"
		tmp = EVALUATION.split('%')
		CORRECTLY = tmp[0] + ' %'
		INCORRECTLY = tmp[1] + ' %'
		TOTAL = EVALUATION[EVALUATION.find('Total'):]
		return CORRECTLY,INCORRECTLY,TOTAL
	except:
		print "\n[ERROR] Formatting Evaluation Results"
	

# analizza l'elenco dei permessi richiesti dall'applicazione per determinare se è un malware
def PermissionsAnalyzer(PERMISSIONS, TOOLSDIR):
	try:
		CP_PATH = TOOLSDIR + 'AndroidPermissionsClassifier.jar'
		TMP = []
		args = ['java', '-jar', CP_PATH, 'classify']
		for permission in PERMISSIONS:
			TMP.append(permission)
			for i in TMP:
				prm = i
				TMP.remove(i)
				pos = i.rfind(".")
				if pos != -1:
					prm = i[pos+1:]
				args.append(prm)
		print "\n[INFO] Calling Android Permissions Classifier"
		print "\n[INFO] Executing Command - " + ' '.join(args)
		ret = subprocess.check_output(args)
		print "\n[INFO] AndroidPermissionsClassifier result: " + ret
		output = "undefined"
		if ret[0] == '0':
			output = "good"
		elif ret[0] == '1':
			output = "malicious"
		return output
	except:
		print "\n[ERROR] Analyzing Permissions"
		return -1
		
# memorizza l'applicazione come istanza del TrainSet del classificatore
def TrainClassifier(PERMISSIONS, TYP, TOOLSDIR):
	try:
		CP_PATH = TOOLSDIR + 'AndroidPermissionsClassifier.jar'
		TMP = []
		args = ['java', '-jar', CP_PATH, TYP]
		for permission in PERMISSIONS:
			TMP.append(permission)
			for i in TMP:
				prm = i
				TMP.remove(i)
				pos = i.rfind(".")
				if pos != -1:
					prm = i[pos+1:]
				args.append(prm)
		print "\n[INFO] Calling Android Permissions Classifier"
		print "\n[INFO] Executing Command - " + ' '.join(args)
		ret = subprocess.check_output(args)
		print "\n[INFO] AndroidPermissionsClassifier result:\n" + ret
		return ret
	except:
		print "\n[ERROR] Analyzing Permissions"
		return -1
		
# restituisce il path di adb.exe
def getADB(TOOLSDIR):
	try:
		adb = 'adb'
		if platform.system() == "Windows":
			adb = os.path.join(TOOLSDIR, 'adb/windows/adb.exe')
		return adb
	except:
		print "\n[ERROR] Getting ADB Location"
		return "adb"

# estrae il contenuto dell'apk
def Unzip(APP_PATH, EXT_PATH):
	print "\n[INFO] Unzipping"
	try:
		files = []
		with zipfile.ZipFile(APP_PATH, "r") as z:
			z.extractall(EXT_PATH)
			files = z.namelist()
		return files
	except:
		print "\n[ERROR] Unzipping Error"
		
# legge e restituisce l'Android Manifest dell'applicazione
def ReadManifest(APP_DIR, TOOLSDIR):
	try:
		dat = ''
		print "\n[INFO] Getting Manifest from Binary"
		print "\n[INFO] AXML -> XML"
		manifest = os.path.join(APP_DIR, "AndroidManifest.xml")
		CP_PATH = TOOLSDIR + 'AXMLPrinter2.jar'
		args = ['java', '-jar', CP_PATH, manifest]
		dat = subprocess.check_output(args)
		return dat
	except:
		print "\n[ERROR] Reading Manifest file"

# effettua il parsing dell'Android Manifest		
def GetManifest(APP_DIR, TOOLSDIR):
	try:
		dat = ''
		mfest = ''
		dat = ReadManifest(APP_DIR, TOOLSDIR).replace("\n", "")
		try:
			print "\n[INFO] Parsing AndroidManifest.xml"
			mfest = minidom.parseString(dat)
		except:
			print "\n[ERROR] Pasrsing AndroidManifest.xml"
			mfest = minidom.parseString(r'<?xml version="1.0" encoding="utf-8"?><manifest xmlns:android="http://schemas.android.com/apk/res/android" android:versionCode="Failed"  android:versionName="Failed" package="Failed"  platformBuildVersionCode="Failed" platformBuildVersionName="Failed XML Parsing" ></manifest>')
			print "\n[WARNING] Using Fake XML to continue the Analysis"
		return mfest
	except:
		print "\n[ERROR] Parsing Manifest file"

# recupera le informazioni utili contenute nell'Android Manifest	
def ManifestData(mfxml, app_dir):
	try:
		print "\n[INFO] Extracting Manifest Data"
		ACT = []
		PERM = []
		DP = {}
		package = ''
		mainact = ''
		permissions = mfxml.getElementsByTagName("uses-permission")
		manifest = mfxml.getElementsByTagName("manifest")
		activities = mfxml.getElementsByTagName("activity")
		for node in manifest:
			package = node.getAttribute("package")
		for activity in activities:
			act = activity.getAttribute("android:name")
			ACT.append(act)
			if len(mainact) < 1:
				for sitem in activity.getElementsByTagName("action"):
					val = sitem.getAttribute("android:name")
					if val == "android.intent.action.MAIN":
						mainact = activity.getAttribute("android:name")
				if mainact == '':
					for sitem in activity.getElementsByTagName("category"):
						val = sitem.getAttribute("android:name")
						if val == "android.intent.category.LAUNCHER":
							mainact = activity.getAttribute("android:name")
		for permission in permissions:
			perm = permission.getAttribute("android:name")
			PERM.append(perm)
		for i in PERM:
			prm = i
			pos = i.rfind(".")
			if pos != -1:
				prm = i[pos+1:]
			try:
				DP[i] = DVM_PERMISSIONS["MANIFEST_PERMISSION"][prm]
			except KeyError:
				DP[i] = [ "dangerous", "Unknown permission from android reference", "Unknown permission from android reference" ]
		return DP,package,mainact
	except:
		print "\n[ERROR] Extracting Manifest Data"
		
# connette il sistema al dispositivo fisico, installa l'app da testare e l'avvia		
def InstallRun(TOOLSDIR, APKPATH, PACKAGE, LAUNCH, isACT):
	print "\n[INFO] Starting App for Dynamic Analysis"
	try:
		adb = getADB(TOOLSDIR)
		print "\n[INFO] ADB Started"
		Wait(5)
		print "\n[INFO] Installing APK"
		subprocess.call([adb, "install", APKPATH])
		if isACT:
			runApp = PACKAGE + "/" + LAUNCH
			print "\n[INFO] Launching APK Main Activity"
			subprocess.call([adb, "shell", "am", "start", "-n", runApp])
		else:
			print "\n[INFO] App Doesn't have a Main Activity"	
		print "\n[INFO] Testing Environment is Ready!"	
	except:
		print "\n[ERROR] Starting App for Dynamic Analysis"
		
# prima di terminare l'esecuzione dell'applicazione vengono raccolti tutti i dati utili		
def DataLogCollection(TOOLSDIR, APKDIR):
		print "\n[INFO] Collecting Data"
		try:
			adb = getADB(TOOLSDIR)
			os.system(adb + ' logcat -d dalvikvm:W ActivityManager:I > ' + APKDIR + 'logcat.txt')
			print "\n[INFO] Collecting Logcat logs"
			os.system(adb + ' shell dumpsys > ' + APKDIR + 'dump.txt')
			print "\n[INFO] Collecting Dumpsys logs"	
		except:
			print "\n[ERROR] Collecting Data"
			
# termina l'esecuzione dell'app e la disinstalla		
def StopRun(TOOLSDIR, PACKAGE):
	print "\n[INFO] Stopping App"
	try:
		adb = getADB(TOOLSDIR)
		#subprocess.call([adb, "shell", "am", "force-stop", PACKAGE])
		subprocess.call([adb, "shell", "pm", "uninstall", PACKAGE])
		print "\n[INFO] Application Uninstalled!"
		pid = ProcessPID()
		print "\n[INFO] Process adb.exe PID: " + pid
		subprocess.call(["taskkill", "/PID", pid, "/F"])
		print "\n[INFO] Process adb killed!"
	except:
		print "\n[ERROR] Stopping App!"

# recupera il PID del processo da killare		
def ProcessPID():
	tl = os.popen("tasklist").readlines()
	for line in tl:
		try:
			p_name = str(line[0:7])
			p_pid = str(line[30:34])
			if p_name == 'adb.exe':
				prog_pid = p_pid
				break
		except:
			pass
	return prog_pid