from django.db import models
from django.db.models.fields import CharField


INVALID, IP, DOM, HASH = 0, 1, 2, 3
ACT, ER, RUN = 1, 2, 3
UNKNOWN, MAL, SUS, SA = 0, 1, 2, 3

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

    INVALID, IP, DOM, HASH = 0, 1, 2, 3
    ACT, ER, RUN = 1, 2, 3
    UNKNOWN, MAL, SUS, SA = 0, 1, 2, 3

    SPECIMEN_CHOICES = ((INVALID, 'INVALID'), (IP, 'IPADDRESS'), 
                        (DOM, 'DOMAIN'), (HASH, 'FILEHASH'))
    ANALYSIS_STATUS = ((UNKNOWN, 'UNKNOWN'), (MAL, 'MALICIOUS'), 
                        (SUS, 'SUSPICIOUS'),(SA, 'SAFE'))
    # CURRENT_STATUS = ((ACT, 'ACTIVE'), (ER, 'ERROR'), (RUN, 'RUNNING'))    
    
    data_id = CharField(max_length=100, unique=True, null=False)
    analyzing_type = models.IntegerField(null=True, choices=SPECIMEN_CHOICES)
    gui_url = models.URLField(null=True)
    last_analyzed = models.DateTimeField(auto_now=True)
    malicious_level = models.IntegerField(null=True, choices=ANALYSIS_STATUS)
    # slug = models.SlugField(max_length=30)
    # status = models.IntegerField(default=1, choices=CURRENT_STATUS)

    class Meta:
        verbose_name = 'OSINT Data'
        verbose_name_plural = 'OSINT Data List'
        ordering = ('data_id',)
    
    def __str__(self) -> str:
        return self.data_id


class VtSummary(models.Model):

    ANALYSIS_STATUS = ((UNKNOWN, 'UNKNOWN'), (MAL, 'MALICIOUS'), 
                        (SUS, 'SUSPICIOUS'),(SA, 'SAFE'))


    osint_id = models.ForeignKey('DataList', on_delete=models.CASCADE)
    owner = CharField(max_length=100, null=True)
    gui_url = models.URLField(null=True)
    malicious_level = models.IntegerField(null=True, choices=ANALYSIS_STATUS)
    malicious_possibility = models.IntegerField(null=True,
                                                choices=ANALYSIS_STATUS)
    last_analyzed = models.DateTimeField(auto_now=True)
    pass

    class Meta:
        verbose_name = 'OSINT Data'
        verbose_name_plural = 'VT Summary'
        ordering = ('osint_id',)

    def __str__(self) -> str:
        str_osint_id = str(self.osint_id)
        return str_osint_id


class OsintSearchHistory(models.Model):
    osint_id = models.ForeignKey('DataList', on_delete=models.CASCADE)
    date = models.DateTimeField(null=False, blank=False)
    from_ip = models.CharField(verbose_name='from ipaddr', max_length=16)
    
    class Meta:
        verbose_name = 'OSINT'
        verbose_name_plural = 'OSINT Search History'
        ordering = ('osint_id',)
    
    def __str__(self) -> str:
        return self.osint_id
