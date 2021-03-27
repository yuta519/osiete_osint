from django.db import models
from django.db.models.fields import CharField

# Create your models here.
class Service(models.Model):
    name = models.CharField(max_length=255)
    slug = models.SlugField(max_length=30, unique=True)
    url = models.URLField()
    
    class Meta:
        verbose_name = 'service'
        verbose_name_plural = 'service'
        ordering = ('name',)
    
    def __str__(self) -> str:
        return self.name


class DataList(models.Model):

    IP, DOM, HASH = 1, 2, 3
    ACT, ER, RUN = 1, 2, 3
    UN, MAL, SUS, SA = 0, 1, 2, 3

    SPECIMEN_CHOICES = ((IP, 'IPADDRESS'), (DOM, 'DOMAIN'), (HASH, 'FILEHASH'))
    # CURRENT_STATUS = ((ACT, 'ACTIVE'), (ER, 'ERROR'), (RUN, 'RUNNING'))
    ANALYSIS_STATUS = ((UN, 'UNKNOWN'), (MAL, 'MALICIOUS'), (SUS, 'SUSPICIOUS'),
                        (SA, 'SAFE'))

    data_id = CharField(max_length=100, unique=True, null=False)
    analyzing_type = models.IntegerField(null=True, choices=SPECIMEN_CHOICES)
    gui_url = models.URLField(null=True)
    last_analyzed = models.DateTimeField(null=True, blank=True)
    malicious_level = models.IntegerField(null=True, choices=ANALYSIS_STATUS)
    # slug = models.SlugField(max_length=30)
    # status = models.IntegerField(default=1, choices=CURRENT_STATUS)

    class Meta:
        verbose_name = 'Analyzed Data List'
        verbose_name_plural = 'Analyzed Data List'
        ordering = ('data_id',)
    
    def __str__(self) -> str:
        return self.data_id
