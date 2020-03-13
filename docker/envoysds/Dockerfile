FROM alpine:3.11
RUN apk add --update bash ca-certificates
COPY cmd/envoysds/envoysds /bin/envoysds
CMD ["/bin/envoysds"]
