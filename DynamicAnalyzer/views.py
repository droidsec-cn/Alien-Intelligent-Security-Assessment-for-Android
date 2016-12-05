# -*- coding: utf_8 -*-
from django.shortcuts import render
from django.http import HttpResponse
from django.http import HttpResponseRedirect
from django.conf import settings
from Alien.views import *
from Analyzer import Unzip,GetManifest,ManifestData,FormatPermissions,FormatEvaluation,PermissionsAnalyzer,TrainClassifier,InstallRun,DataLogCollection,StopRun
import subprocess,platform

PACKAGE = ''
MAINACTIVITY = ''
APP_DIR = ''
APK = ''
PERMISSIONS = ''

# inizializza l'analisi statica del file
def StaticAnalyzer(request):
	print "\n[INFO] Static Analysis Started"
	try:
		if request.method == 'GET':
			NAME = request.GET['name']
			MD5 = request.GET['checksum']
			TYP = request.GET['type']
			if TYP == 'apk':
				global APP_DIR
				global PACKAGE
				global PERMISSIONS
				global MAINACTIVITY
				global APK
				APP_DIR = settings.UPLD_DIR + MD5 + '/'
				APP_FILE = MD5 + '.apk'
				APK = APP_DIR + APP_FILE
				FILES = Unzip(APK, APP_DIR)
				print "\n[INFO] APK Extracted"
				PARSEDXML = GetManifest(APP_DIR, settings.TOOLSDIR)
				PERMISSIONS,PACKAGE,MAINACTIVITY = ManifestData(PARSEDXML, APP_DIR)
				PERM = FormatPermissions(PERMISSIONS)
				MALWARE = PermissionsAnalyzer(PERMISSIONS, settings.TOOLSDIR)
				print "\n[INFO] Package name: " + PACKAGE
				print "\n[INFO] Main Activity: " + MAINACTIVITY
				context = {
					'title' : 'Static Analysis',
					'name' : NAME,
					'md5' : MD5,
					'type' : MALWARE,
					'package' : PACKAGE,
					'mainactivity' : MAINACTIVITY,
					'permissions' : PERM,
					'files' : FILES,
				}
				template = "static_analysis.html"
				return render(request, template, context)
			else:
				print "\n[ERROR] Only APK files supported!"
		else:
			return HttpResponseRedirect('/error/')		
	except:
		print "\n[ERROR] Static Analyzer"
        return HttpResponseRedirect('/error/')
		
# gestisce il file apk utilizzato per addestrare il classificatore
def Train(request):
	try:
		if request.method == 'POST':
			form = UploadTrainForm(request.POST)
			if form.is_valid():
				TYP = request.POST['app-type']
				print "\n[INFO] Application type: " + TYP
				EVALUATION = TrainClassifier(PERMISSIONS, TYP, settings.TOOLSDIR)
				CORRECTLY,INCORRECTLY,TOTAL = FormatEvaluation(EVALUATION)
				context = {
					'title' : 'K-Fold Cross Validation',
					'correctly' : CORRECTLY,
					'incorrectly' : INCORRECTLY,
					'total' : TOTAL,
				}
				template = "train_classifier.html"
				return render(request, template, context)
			else:
				url = '/error/'
				print "\n[ERROR] Invalid Form Data!"
		else:
			form = UploadTrainForm()
			print "\n[ERROR] Method not Supported!"
		return HttpResponseRedirect(url)
	except:
		print "\n[ERROR] Uploading Train File!"
	
# esegue l'analisi dinamica dell'applicazione selezionata		
def StartAnalysis(request):
	try:
		adb = getADB(settings.TOOLSDIR)
		ExecuteCMD([adb, "kill-server"])
		ExecuteCMD([adb, "start-server"])
		InstallRun(settings.TOOLSDIR, APK, PACKAGE, MAINACTIVITY, True)
		context = {}
		template = "dynamic_analysis.html"
		return render(request, template, context)
	except:
		print "\n[ERROR] Dynamic Analyzer"
		return HttpResponseRedirect('/error/')
        

# colleziona i dati dell'analisi, quindi disinstalla l'applicazione analizzata	
def FinishAnalysis(request):
	try:
		DataLogCollection(settings.TOOLSDIR, APP_DIR)
		StopRun(settings.TOOLSDIR, PACKAGE)
		context = {}
		template = "finish_analysis.html"
		return render(request, template, context)
	except:
		print "\n[ERROR] Finish Dynamic Analysis"
		return HttpResponseRedirect('/error/')
		
# esegue un comando passato in input con relativi parametri
def ExecuteCMD(args, ret=False):
	try:
		print "\n[INFO] Executing Command - " + ' '.join(args)
		if ret:
			return subprocess.check_output(args)
		else:
			subprocess.call(args)
	except Exception as e:
		print ("\n[ERROR] Executing Command - " + str(e))
		
# restituisce il path dell'android debug bridge 
def getADB(TOOLSDIR):
	print "\n[INFO] Getting ADB Location"
	try:
		adb = 'adb'
		if platform.system() == "Windows":
			adb = os.path.join(TOOLSDIR, 'adb/windows/adb.exe')
		return adb
	except Exception as e:
		print ("\n[ERROR] Getting ADB Location - " + str(e))
		return "adb"