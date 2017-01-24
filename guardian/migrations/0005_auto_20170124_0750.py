# -*- coding: utf-8 -*-
# Generated by Django 1.9.1 on 2017-01-24 07:50
from __future__ import unicode_literals

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('guardian', '0004_auto_20170104_1622'),
    ]

    operations = [
        migrations.AddField(
            model_name='groupobjectpermission',
            name='origin',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='guardian.Origin'),
        ),
        migrations.AlterField(
            model_name='userobjectpermission',
            name='origin',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='guardian.Origin'),
        ),
        migrations.AlterUniqueTogether(
            name='groupobjectpermission',
            unique_together=set([('group', 'permission', 'object_pk', 'origin')]),
        ),
    ]
