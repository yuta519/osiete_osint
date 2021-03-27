# Generated by Django 3.1.7 on 2021-03-25 10:51

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('service', '0005_delete_securityspecimen'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='datalist',
            options={'ordering': ('gui_url',), 'verbose_name': 'Analyzed Data List', 'verbose_name_plural': 'Analyzed Data List'},
        ),
        migrations.RenameField(
            model_name='datalist',
            old_name='result_url',
            new_name='gui_url',
        ),
        migrations.RemoveField(
            model_name='datalist',
            name='status',
        ),
        migrations.AlterField(
            model_name='datalist',
            name='analyzing_type',
            field=models.IntegerField(choices=[(1, 'IPADDRESS'), (2, 'DOMAIN'), (3, 'FILEHASH')], null=True),
        ),
        migrations.AlterField(
            model_name='datalist',
            name='malicous_level',
            field=models.IntegerField(choices=[(0, 'UNKNOWN'), (1, 'MALICIOUS'), (2, 'SUSPICIOUS'), (3, 'SAFE')]),
        ),
    ]
