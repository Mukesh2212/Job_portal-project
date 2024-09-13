ARG PYTHON_VERSION=3.8

FROM python:${PYTHON_VERSION}

ENV APP_HOME /app

WORKDIR $APP_HOME

RUN pip install --no-cache-dir -r requirements.txt

RUN mkdir $APP_HOME/storage

VOLUME ["$APP_HOME/storage"] 

ENTRYPOINT ["python", "manage.py"]

CMD ["runserver", "0.0.0.0:8000"]



# COPY . $APP_HOME
# ADD requirements.txt $APP_HOME/

# EXPOSE 8000



FROM mysql:latest

ENV MYSQL_ROOT_PASSWORD=root

