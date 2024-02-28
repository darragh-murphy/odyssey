@echo off

rem Function to check if Apache Maven is installed
:check_maven
where mvn >nul 2>nul
if %errorlevel% equ 0 (
    echo Apache Maven found.
    call :build_project
) else (
    echo Apache Maven not found.
    echo Please install Apache Maven and try again.
    exit /b 1
)

rem Function to build the project using Apache Maven
:build_project
echo Building the project...
mvn clean install
exit /b

rem Main function
:main
rem Directories to search for Apache Maven installation
set "maven_directories=/opt/maven /usr/share/maven /usr/local/maven /opt/apache-maven %USERPROFILE%\apache-maven"

rem Check if Maven is installed in any of the directories
for %%d in (%maven_directories%) do (
    if exist "%%d\bin\mvn.cmd" (
        set "PATH=%%d\bin;%PATH%"
        echo Apache Maven found in %%d.
        call :build_project
        exit /b
    )
)

rem Maven not found, prompt user to install it
echo Apache Maven is required to build the project.
echo Please install Apache Maven and try again.
exit /b 1
