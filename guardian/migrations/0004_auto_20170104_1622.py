# -*- coding: utf-8 -*-
# Generated by Django 1.9.1 on 2017-01-04 16:22
from __future__ import unicode_literals

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('guardian', '0003_auto_20161207_1618'),
    ]

    operations = [
        migrations.AlterField(
            model_name='userobjectpermission',
            name='origin',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='guardian.Origin'),
        ),
    ]
