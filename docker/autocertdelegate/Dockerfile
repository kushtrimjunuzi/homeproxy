FROM alpine:3.11
RUN apk add --update bash ca-certificates
ADD cmd/autocertdelegate/autocertdelegate /bin/autocertdelegate
CMD ["/bin/autocertdelegate"]
