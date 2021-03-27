# Generated by Django 3.1.7 on 2021-03-25 10:57

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('service', '0008_remove_datalist_slug'),
    ]

    operations = [
        migrations.AlterField(
            model_name='datalist',
            name='malicous_level',
            field=models.IntegerField(choices=[(0, 'UNKNOWN'), (1, 'MALICIOUS'), (2, 'SUSPICIOUS'), (3, 'SAFE')], null=True),
        ),
    ]
