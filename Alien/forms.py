# -*- coding: utf_8 -*-
from django import forms

# classe che gestisce l'upload dell'applicazione da analizzare
class UploadFileForm(forms.Form):
    file = forms.FileField()
	
# classe che gestisce l'upload dell'applicazione da utilizzare per addestrare il classificatore
class UploadTrainForm(forms.Form):
	type = forms.RadioSelect()