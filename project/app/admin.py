from django.contrib import admin
from . import models
# Register your models here.
admin.site.register(models.CustomUser)
admin.site.register(models.Stream)
admin.site.register(models.Report)
admin.site.register(models.Category)
admin.site.register(models.Message)
admin.site.register(models.Chat)