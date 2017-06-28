# -*- coding: utf-8 -*-
# Generated by Django 1.9.1 on 2017-06-28 17:35
from __future__ import unicode_literals

import uuid

from django.db import migrations
from django.db import models


def add_uuids(apps, schema_director):
    Origin = apps.get_model('guardian', 'Origin')
    for origin in Origin.objects.all():
        origin.uuid = uuid.uuid4()
        origin.save()


class Migration(migrations.Migration):

    dependencies = [
        ('guardian', '0006_auto_20170124_0803'),
    ]

    operations = [
        migrations.AddField(
            model_name='origin',
            name='uuid',
            field=models.UUIDField(unique=False, null=True),
        ),
        migrations.RunPython(
            code=add_uuids,
            reverse_code=lambda apps, schema_editor: None
        ),
        migrations.AlterField(
            model_name='origin',
            name='uuid',
            field=models.UUIDField(default=uuid.uuid4, unique=True, null=False),
        ),
    ]
