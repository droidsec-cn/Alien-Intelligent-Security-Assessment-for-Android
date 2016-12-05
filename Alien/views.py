# -*- coding: utf_8 -*-
from django.http import HttpResponse
from django.http import HttpResponseRedirect
from django.shortcuts import render
from django.conf import settings
from .forms import UploadFileForm,UploadTrainForm
import os,hashlib

# carica l'homepage di Alien
def index(request):
    context = {}
    template = "index.html"
    return render(request, template, context)
	
# calcola l'md5 del file ricevuto in input e lo traferisce nella cartella apposita
def handle_uploaded_file(f, typ):
    md5 = hashlib.md5() 
    for chunk in f.chunks():
        md5.update(chunk)
    md5sum = md5.hexdigest()
    ANAL_DIR = os.path.join(settings.UPLD_DIR, md5sum + '/')
    if not os.path.exists(ANAL_DIR):
        os.makedirs(ANAL_DIR)
    with open(ANAL_DIR + md5sum + typ, 'wb+') as destination:
        for chunk in f.chunks():
            destination.write(chunk) 
    return md5sum

# gestisce il file apk passato in input per l'upload	
def Upload(request):
	try:
		if request.method == 'POST':
			form = UploadFileForm(request.POST, request.FILES)
			if form.is_valid():
				file_type = request.FILES['file'].content_type
				print "\n[INFO] MIME Type: " + file_type + " FILE: " + str(request.FILES['file'].name)
				if(file_type == "application/octet-stream" or file_type == "application/vnd.android.package-archive") and request.FILES['file'].name.endswith('.apk'):
					MD5 = handle_uploaded_file(request.FILES['file'], '.apk')
					url = '/DynamicAnalyzer/?name=' + request.FILES['file'].name + '&type=apk&checksum=' + MD5
				else:
					url = '/error/'
					print "\n[ERROR] File format not Supported!"
			else:
				url = '/error/'
				print "\n[ERROR] Invalid Form Data!"
		else:
			form = UploadFileForm()
			print "\n[ERROR] Method not Supported!"
		return HttpResponseRedirect(url)
	except:
		print "\n[ERROR] Uploading File!"
		
# in seguito ad un errore visualizza la schermata corrispondente		
def error(request):
	context = {}
	template = "error.html"
	return render(request, template, context)