# -*- coding: utf_8 -*-
from django.conf.urls import include, url
from django.contrib import admin

urlpatterns = [
	url(r'^$', 'Alien.views.index', name = 'index'),
	url(r'^Upload/$', 'Alien.views.Upload', name = 'Upload'),
	url(r'^Train/$', 'DynamicAnalyzer.views.Train', name = 'Train'),
	url(r'^DynamicAnalyzer/$', 'DynamicAnalyzer.views.StaticAnalyzer', name = 'StaticAnalyzer'),
	url(r'^StartAnalysis/$', 'DynamicAnalyzer.views.StartAnalysis', name = 'StartAnalysis'),
	url(r'^StopAnalysis/$', 'DynamicAnalyzer.views.FinishAnalysis', name = 'FinishAnalysis'),
	url(r'^error/$', 'Alien.views.error', name = 'error'),
]
