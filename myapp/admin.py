from django.contrib import admin
from myapp.models import *

class Todoadmin(admin.ModelAdmin):
    list_display = ('id','task','updated','completed')

admin.site.register(Todo,Todoadmin)


class Snippetadmin(admin.ModelAdmin):
    list_display = ('id','created','title','code','linenos','language','style')

admin.site.register(Snippet,Snippetadmin)
