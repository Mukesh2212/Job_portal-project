# Generated by Django 4.2.5 on 2024-10-22 06:22

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='EmployeeDashboard',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=150)),
                ('email', models.EmailField(max_length=254, unique=True)),
                ('phone_number', models.CharField(max_length=13)),
                ('message', models.TextField()),
                ('upload_file', models.FileField(upload_to='uploads/')),
                ('upload_img', models.ImageField(upload_to='uploadsimg/')),
            ],
        ),
        migrations.CreateModel(
            name='EmployerDashboard',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('select_date', models.DateField(auto_created=True)),
                ('select_time', models.TimeField(auto_now=True)),
                ('problem_type', models.CharField(choices=[('bug', 'Bug'), ('feature', 'Feature Request'), ('support', 'Support'), ('other', 'Other')], max_length=200)),
                ('explain_the_problem', models.TextField()),
            ],
        ),
    ]