<cfcomponent>
    <!--- Application settings --->
    <cfset this.name = "TestApplication">
    <cfset this.sessionManagement = true>
    <cfset this.sessionTimeout = createTimeSpan(0, 0, 30, 0)>
    <cfset this.applicationTimeout = createTimeSpan(1, 0, 0, 0)>
    
    <!--- Application start --->
    <cffunction name="onApplicationStart" returntype="boolean">
        <cfset application.startTime = now()>
        <cfset application.name = "CFML Test Application">
        <cflog text="Application started">
        <cfreturn true>
    </cffunction>
    
    <!--- Session start --->
    <cffunction name="onSessionStart">
        <cfset session.created = now()>
        <cfset session.pageViews = 0>
    </cffunction>
    
    <!--- Request start --->
    <cffunction name="onRequestStart" returntype="boolean">
        <cfargument name="targetPage" type="string" required="true">
        
        <!--- Increment page views --->
        <cfif isDefined("session.pageViews")>
            <cfset session.pageViews = session.pageViews + 1>
        </cfif>
        
        <cfreturn true>
    </cffunction>
    
    <!--- Request processing --->
    <cffunction name="onRequest">
        <cfargument name="targetPage" type="string" required="true">
        <cfinclude template="#arguments.targetPage#">
    </cffunction>
    
    <!--- Request end --->
    <cffunction name="onRequestEnd">
        <cfargument name="targetPage" type="string" required="false">
        <!--- Cleanup if needed --->
    </cffunction>
    
    <!--- Error handling --->
    <cffunction name="onError">
        <cfargument name="exception" required="true">
        <cfargument name="eventName" type="string" required="false" default="">
        
        <cflog text="Error in #arguments.eventName#: #arguments.exception.message#" type="error">
        
        <cfoutput>
            <h1>An Error Occurred</h1>
            <p>We're sorry, but an error has occurred while processing your request.</p>
            <cfif isDefined("arguments.exception.message")>
                <p><strong>Error:</strong> #arguments.exception.message#</p>
            </cfif>
        </cfoutput>
    </cffunction>
    
    <!--- Session end --->
    <cffunction name="onSessionEnd">
        <cfargument name="sessionScope" required="true">
        <cfargument name="applicationScope" required="true">
        <cflog text="Session ended">
    </cffunction>
    
    <!--- Application end --->
    <cffunction name="onApplicationEnd">
        <cfargument name="applicationScope" required="true">
        <cflog text="Application ended">
    </cffunction>
</cfcomponent>
