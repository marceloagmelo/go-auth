FROM marceloagmelo/golang-1.13 AS builder

LABEL maintainer="Marcelo Melo marceloagmelo@gmail.com"

USER root

ENV APP_HOME /go/src/github.com/marceloagmelo/go-auth

ADD . $APP_HOME

WORKDIR $APP_HOME

# RUN go get ./... && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o go-auth && \
RUN go mod init && \
    go install && \
    rm -Rf /tmp/* && rm -Rf /var/tmp/*

###
# IMAGEM FINAL
###
FROM centos:7

ENV GID 23550
ENV UID 23550
ENV USER golang

ENV APP_BUILDER /go/bin
ENV APP_HOME /opt/app

WORKDIR $APP_HOME

COPY --from=builder $APP_BUILDER/go-auth $APP_HOME/go-auth
COPY docker-container-start.sh $APP_HOME
COPY Dockerfile $APP_HOME/Dockerfile

RUN groupadd --gid $GID $USER && useradd --uid $UID -m -g $USER $USER && \
    chown -fR $USER:0 $APP_HOME && \
    rm -Rf /tmp/* && rm -Rf /var/tmp/*

ENV PATH $APP_HOME:$PATH

EXPOSE 8080

USER ${USER}

ENTRYPOINT [ "./docker-container-start.sh" ]
CMD [ "go-auth" ]
