# Generated by Django 3.1.7 on 2021-05-19 06:54

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('service', '0026_urlscan'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='datalist',
            name='gui_url',
        ),
    ]
