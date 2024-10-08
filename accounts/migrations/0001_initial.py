# Generated by Django 4.2.5 on 2024-08-27 12:49

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='CustomUser',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('password', models.CharField(max_length=128, verbose_name='password')),
                ('last_login', models.DateTimeField(blank=True, null=True, verbose_name='last login')),
                ('email', models.EmailField(max_length=254, unique=True)),
                ('full_name', models.CharField(default='null', max_length=255)),
                ('is_active', models.BooleanField(default=True)),
                ('is_admin', models.BooleanField(default=False)),
                ('is_staff', models.BooleanField(default=False)),
                ('terms_and_conditions', models.BooleanField(default=False)),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='AdvancedJobSearch',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('jobRole', models.CharField(max_length=100)),
                ('jobType', models.CharField(max_length=100)),
                ('minExp', models.CharField(max_length=100)),
                ('maxExp', models.CharField(max_length=100)),
                ('minSal', models.CharField(max_length=100)),
                ('maxSal', models.CharField(max_length=100)),
                ('location', models.CharField(max_length=100)),
                ('industry', models.CharField(max_length=100)),
            ],
        ),
        migrations.CreateModel(
            name='Blog',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(max_length=255)),
                ('author_name', models.CharField(max_length=255)),
                ('author_email', models.CharField(max_length=255)),
                ('date_of_submission', models.CharField(max_length=255)),
                ('blog_content', models.TextField()),
                ('category', models.TextField()),
                ('keywords_tags', models.CharField(blank=True, max_length=255, null=True)),
                ('author_bio', models.TextField()),
                ('author_profile_picture', models.ImageField(blank=True, null=True, upload_to='author_profile_pics/')),
                ('media_files', models.FileField(default='null', max_length=255, upload_to='blog_files/')),
            ],
        ),
        migrations.CreateModel(
            name='BookDemo',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('full_name', models.CharField(max_length=255)),
                ('company_name', models.CharField(max_length=255)),
                ('business_name', models.CharField(max_length=255)),
                ('number_of_employees', models.PositiveIntegerField()),
                ('mobile_number', models.CharField(max_length=15)),
            ],
        ),
        migrations.CreateModel(
            name='BoostnowProfileForm',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('full_name', models.CharField(max_length=100)),
                ('email', models.EmailField(max_length=254)),
                ('phone', models.CharField(max_length=20)),
                ('education', models.TextField()),
                ('work_experience', models.TextField()),
            ],
        ),
        migrations.CreateModel(
            name='ContactDetails',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('fullname', models.CharField(max_length=255)),
                ('phonenNumber', models.CharField(max_length=20)),
                ('email', models.CharField(max_length=255)),
                ('subject', models.CharField(blank=True, max_length=255, null=True)),
                ('description', models.CharField(blank=True, max_length=255, null=True)),
            ],
        ),
        migrations.CreateModel(
            name='Course',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('course_name', models.CharField(max_length=100)),
                ('certification', models.CharField(max_length=100)),
                ('completion_date', models.DateField()),
            ],
        ),
        migrations.CreateModel(
            name='Employer',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('username', models.CharField(max_length=255)),
                ('email', models.EmailField(max_length=254, unique=True)),
                ('password', models.CharField(max_length=128)),
                ('terms_and_conditions', models.BooleanField(default=False)),
            ],
        ),
        migrations.CreateModel(
            name='EmployerRegistration',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('first_name', models.CharField(max_length=100)),
                ('last_name', models.CharField(max_length=100)),
                ('email', models.EmailField(max_length=255, unique=True)),
                ('company_name', models.CharField(max_length=255)),
                ('company_type', models.CharField(choices=[('Freelancer', 'Freelancer'), ('Proprietorship', 'Proprietorship'), ('Partnership', 'Partnership'), ('LLP', 'LLP'), ('Pvt Ltd', 'Private Limited')], max_length=20)),
                ('upload_document_1', models.FileField(blank=True, null=True, upload_to='documents/')),
                ('upload_document_2', models.FileField(blank=True, null=True, upload_to='documents/')),
                ('upload_document_3', models.FileField(blank=True, null=True, upload_to='documents/')),
                ('company_pan_card', models.FileField(upload_to='pan_cards/')),
                ('phone_number', models.CharField(max_length=15)),
                ('contact_person_name', models.CharField(max_length=100)),
                ('contact_person_phone_number', models.CharField(max_length=15)),
            ],
        ),
        migrations.CreateModel(
            name='Job',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('jobType', models.CharField(max_length=100)),
                ('jobRole', models.CharField(max_length=100)),
                ('companyType', models.CharField(max_length=100)),
                ('companyName', models.CharField(max_length=100)),
                ('workMode', models.CharField(max_length=100)),
                ('minExp', models.CharField(max_length=100)),
                ('maxExp', models.CharField(max_length=100)),
                ('minSal', models.CharField(max_length=100)),
                ('maxSal', models.CharField(max_length=100)),
                ('location', models.CharField(max_length=100)),
                ('industry', models.CharField(max_length=100)),
                ('jobDescription', models.CharField(max_length=1000)),
                ('educationRequirement', models.CharField(max_length=100)),
                ('applicationLink', models.CharField(max_length=200)),
                ('companyDescription', models.CharField(max_length=1000)),
                ('contactInfo', models.CharField(max_length=100)),
                ('postingDate', models.CharField(max_length=100)),
                ('expiringDate', models.CharField(max_length=100)),
            ],
        ),
        migrations.CreateModel(
            name='MyProfile',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100)),
                ('email', models.EmailField(max_length=254)),
                ('phone', models.CharField(max_length=20)),
                ('upload_resume', models.FileField(upload_to='resumes/')),
                ('degree', models.CharField(max_length=100)),
                ('university', models.CharField(max_length=100)),
                ('start_date', models.DateField(blank=True, null=True)),
                ('end_date', models.DateField(blank=True, null=True)),
                ('description_1', models.TextField()),
                ('job_title', models.CharField(max_length=100)),
                ('company', models.CharField(max_length=100)),
                ('job_start_date', models.DateField(blank=True, null=True)),
                ('job_end_date', models.DateField(blank=True, null=True)),
                ('description_2', models.TextField()),
                ('skill_set', models.TextField()),
            ],
        ),
        migrations.CreateModel(
            name='OTP',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('email', models.EmailField(max_length=254)),
                ('otp_code', models.CharField(max_length=6)),
                ('is_verified', models.BooleanField(default=False)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
            ],
        ),
        migrations.CreateModel(
            name='OTPVerifiaction',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('phone_number', models.IntegerField()),
                ('otp', models.CharField(max_length=4)),
                ('is_verfied', models.BooleanField(default=False)),
                ('date', models.CharField(default='2024-08-27', max_length=10)),
            ],
        ),
        migrations.CreateModel(
            name='ProfileHighlighter',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100)),
                ('email', models.EmailField(max_length=254)),
                ('phone', models.CharField(max_length=20)),
                ('education', models.TextField()),
                ('work_experience', models.TextField()),
            ],
        ),
        migrations.CreateModel(
            name='ReviewOnJobs',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('full_name', models.CharField(blank=True, max_length=255, null=True)),
                ('emailphone', models.CharField(blank=True, max_length=255, null=True)),
                ('descriptions', models.CharField(blank=True, max_length=255, null=True)),
                ('rating', models.CharField(blank=True, max_length=255, null=True)),
            ],
        ),
        migrations.CreateModel(
            name='Review',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('job_id', models.CharField(blank=True, max_length=255, null=True)),
                ('message', models.TextField()),
                ('rating', models.IntegerField()),
                ('user_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
