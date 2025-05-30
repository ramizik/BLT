# Generated by Django 5.1.4 on 2025-01-25 19:49

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("website", "0180_rename_project_visit_count_repo_repo_visit_count"),
    ]

    operations = [
        migrations.CreateModel(
            name="TrademarkOwner",
            fields=[
                (
                    "id",
                    models.AutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("name", models.CharField(max_length=255)),
                ("address1", models.CharField(blank=True, max_length=255, null=True)),
                ("address2", models.CharField(blank=True, max_length=255, null=True)),
                ("city", models.CharField(blank=True, max_length=100, null=True)),
                ("state", models.CharField(blank=True, max_length=100, null=True)),
                ("country", models.CharField(blank=True, max_length=100, null=True)),
                ("postcode", models.CharField(blank=True, max_length=20, null=True)),
                ("owner_type", models.CharField(blank=True, max_length=20, null=True)),
                (
                    "owner_label",
                    models.CharField(blank=True, max_length=100, null=True),
                ),
                (
                    "legal_entity_type",
                    models.CharField(blank=True, max_length=20, null=True),
                ),
                (
                    "legal_entity_type_label",
                    models.CharField(blank=True, max_length=100, null=True),
                ),
            ],
        ),
        migrations.CreateModel(
            name="Trademark",
            fields=[
                (
                    "id",
                    models.AutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("keyword", models.CharField(max_length=255)),
                (
                    "registration_number",
                    models.CharField(blank=True, max_length=50, null=True),
                ),
                (
                    "serial_number",
                    models.CharField(blank=True, max_length=50, null=True),
                ),
                (
                    "status_label",
                    models.CharField(blank=True, max_length=50, null=True),
                ),
                ("status_code", models.CharField(blank=True, max_length=20, null=True)),
                ("status_date", models.DateField(blank=True, null=True)),
                (
                    "status_definition",
                    models.CharField(blank=True, max_length=255, null=True),
                ),
                ("filing_date", models.DateField(blank=True, null=True)),
                ("registration_date", models.DateField(blank=True, null=True)),
                ("abandonment_date", models.DateField(blank=True, null=True)),
                ("expiration_date", models.DateField(blank=True, null=True)),
                ("description", models.TextField(blank=True, null=True)),
                (
                    "organization",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="trademarks",
                        to="website.organization",
                    ),
                ),
                (
                    "owners",
                    models.ManyToManyField(related_name="trademarks", to="website.trademarkowner"),
                ),
            ],
        ),
    ]
