# Generated by Django 3.1.7 on 2021-03-22 11:41

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('service', '0002_auto_20210322_1141'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='analyzed',
            options={'ordering': ('result_url',), 'verbose_name': 'Security Analyzed Target', 'verbose_name_plural': 'Security Analyzed Target'},
        ),
    ]
