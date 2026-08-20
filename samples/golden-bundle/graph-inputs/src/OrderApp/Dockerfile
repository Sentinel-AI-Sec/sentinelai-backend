FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base
LABEL org.sentinelai.image="tinyapp/order"
WORKDIR /app
EXPOSE 8080

FROM base AS final
ENTRYPOINT ["dotnet", "OrderApp.dll"]
