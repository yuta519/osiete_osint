from re import T
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
    
    data_id = CharField(max_length=100, unique=True, null=False)
    analyzing_type = models.IntegerField(null=True, choices=SPECIMEN_CHOICES)
    last_analyzed = models.DateTimeField(auto_now=True)
    malicious_level = models.IntegerField(null=True, choices=ANALYSIS_STATUS)

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
    gui_url = models.URLField(null=True, unique=True)
    malicious_level = models.IntegerField(null=True, choices=ANALYSIS_STATUS)
    malicious_possibility = models.IntegerField(null=True,
                                                choices=ANALYSIS_STATUS)
    indexed_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = 'OSINT Data'
        verbose_name_plural = 'VirusTotal Summary'
        ordering = ('osint_id',)

    def __str__(self) -> str:
        str_osint_id = str(self.osint_id)
        return str_osint_id


class VtComments(models.Model):

    vt_summary = models.ForeignKey('VtSummary', on_delete=models.CASCADE)
    date = CharField(max_length=100, null=True)
    comment = CharField(max_length=1000, null=True)

    class Meta:
        verbose_name = 'OSINT'
        verbose_name_plural = 'VirusTotal Comments'
        ordering = ('vt_summary',)

    def __str__(self) -> str:
        str_vt_summary = str(self.vt_summary)
        return str_vt_summary


class UrlScan(models.Model):

    osint_id = models.ForeignKey('DataList', on_delete=models.CASCADE )
    date = models.DateField()
    domain = CharField(max_length=100, unique=True)
    primary_ip = CharField(max_length=20, null=True)
    server = CharField(max_length=20, null=True)
    asnname = CharField(max_length=20, null=True)
    asn = CharField(max_length=20, null=True)
    ptr = CharField(max_length=100, null=True)
    screenshot = models.URLField(null=True)

    class Meta:
        verbose_name = 'OSINT'
        verbose_name_plural = 'urlscan.io information'
        ordering = ('osint_id',)

    def __str__(self) -> str:
        return self.domain 


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
