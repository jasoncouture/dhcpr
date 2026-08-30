ARG BUILDPLATFORM
FROM --platform=${BUILDPLATFORM} harbor.instigaterevolution.com/microsoft/dotnet/sdk:10.0-alpine AS build
ARG TARGETARCH
WORKDIR /src

COPY --link --parents *.slnx **/*.csproj **/*.props **/*.targets ./
RUN dotnet restore src/Dhcpr.Server/Dhcpr.Server.csproj -a "${TARGETARCH}" --os linux-musl -p:Configuration=Release --p:PublishSingleFile=true
COPY . .
RUN dotnet publish src/Dhcpr.Server/Dhcpr.Server.csproj -c Release -o /app/publish -a "${TARGETARCH}" --os linux-musl --no-restore --self-contained --p:PublishSingleFile=true
RUN chmod +x /app/publish/Dhcpr.Server

FROM harbor.instigaterevolution.com/dockerhub/alpine:3.24 AS final
WORKDIR /app
EXPOSE 8080 443 853
ENV DOTNET_URLS=http://+:8080 \
    DataPath=/data \
    DHCP__ENABLED="false" \
    DNS__ROOTSERVERS__DOWNLOAD="true"

VOLUME ["/data"]

RUN mkdir -p /data/dataprotection-keys /data/cache

RUN apk add --no-cache \
    curl \
    icu-data-full \
    icu-libs \
    brotli-libs \
    lttng-ust


COPY --from=build /app/publish /app

RUN chmod +x /app/Dhcpr.Server
ENTRYPOINT ["/app/Dhcpr.Server"]
