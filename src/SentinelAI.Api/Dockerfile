FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS base
USER $APP_UID
WORKDIR /app
EXPOSE 8080
EXPOSE 8081

FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
ARG BUILD_CONFIGURATION=Release
WORKDIR /src
COPY ["src/SentinelAI.Api/SentinelAI.Api.csproj", "src/SentinelAI.Api/"]
COPY ["src/SentinelAI.Application/SentinelAI.Application.csproj", "src/SentinelAI.Application/"]
COPY ["src/SentinelAI.Domain/SentinelAI.Domain.csproj", "src/SentinelAI.Domain/"]
COPY ["src/SentinelAI.Infrastructure/SentinelAI.Infrastructure.csproj", "src/SentinelAI.Infrastructure/"]
RUN dotnet restore "src/SentinelAI.Api/SentinelAI.Api.csproj"
COPY . .
WORKDIR "/src/src/SentinelAI.Api"
RUN dotnet build "./SentinelAI.Api.csproj" -c $BUILD_CONFIGURATION -o /app/build

FROM build AS publish
ARG BUILD_CONFIGURATION=Release
RUN dotnet publish "./SentinelAI.Api.csproj" -c $BUILD_CONFIGURATION -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "SentinelAI.Api.dll"]
