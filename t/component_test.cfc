<cfcomponent displayname="TestComponent" hint="A sample CFC for testing">
    
    <!--- Properties --->
    <cfproperty name="name" type="string" default="">
    <cfproperty name="value" type="numeric" default="0">
    
    <!--- Constructor --->
    <cffunction name="init" access="public" returntype="component_test">
        <cfargument name="name" type="string" required="false" default="unnamed">
        <cfargument name="value" type="numeric" required="false" default="0">
        
        <cfset variables.name = arguments.name>
        <cfset variables.value = arguments.value>
        
        <cfreturn this>
    </cffunction>
    
    <!--- Getters --->
    <cffunction name="getName" access="public" returntype="string">
        <cfreturn variables.name>
    </cffunction>
    
    <cffunction name="getValue" access="public" returntype="numeric">
        <cfreturn variables.value>
    </cffunction>
    
    <!--- Setters --->
    <cffunction name="setName" access="public" returntype="void">
        <cfargument name="name" type="string" required="true">
        <cfset variables.name = arguments.name>
    </cffunction>
    
    <cffunction name="setValue" access="public" returntype="void">
        <cfargument name="value" type="numeric" required="true">
        <cfset variables.value = arguments.value>
    </cffunction>
    
    <!--- Business methods --->
    <cffunction name="double" access="public" returntype="numeric">
        <cfreturn variables.value * 2>
    </cffunction>
    
    <cffunction name="add" access="public" returntype="numeric">
        <cfargument name="num" type="numeric" required="true">
        <cfset variables.value = variables.value + arguments.num>
        <cfreturn variables.value>
    </cffunction>
    
    <cffunction name="toString" access="public" returntype="string">
        <cfreturn "TestComponent[name=#variables.name#, value=#variables.value#]">
    </cffunction>
    
    <!--- Remote method (accessible via HTTP) --->
    <cffunction name="getData" access="remote" returntype="struct" returnformat="json">
        <cfset var result = structNew()>
        <cfset result.name = variables.name>
        <cfset result.value = variables.value>
        <cfset result.doubled = double()>
        <cfreturn result>
    </cffunction>
</cfcomponent>
