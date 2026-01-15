<!DOCTYPE html>
<html>
<head>
    <title>CFML Module Test</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .test { padding: 10px; margin: 10px 0; border-left: 4px solid #ccc; }
        .pass { border-color: green; background: #e8f5e9; }
        .fail { border-color: red; background: #ffebee; }
        h2 { color: #333; }
        code { background: #f5f5f5; padding: 2px 6px; }
    </style>
</head>
<body>
    <h1>ngx_http_cfml_module Test Suite</h1>
    
    <h2>1. Variable Assignment and Output</h2>
    <cfset testVar = "Hello, CFML!">
    <cfoutput>
        <div class="test pass">
            Variable output: #testVar#
        </div>
    </cfoutput>
    
    <h2>2. Numeric Operations</h2>
    <cfset a = 10>
    <cfset b = 3>
    <cfoutput>
        <div class="test pass">
            Addition: #a# + #b# = #a + b#<br>
            Subtraction: #a# - #b# = #a - b#<br>
            Multiplication: #a# * #b# = #a * b#<br>
            Division: #a# / #b# = #a / b#<br>
            Modulo: #a# MOD #b# = #a MOD b#<br>
            Power: #a# ^ #b# = #a ^ b#
        </div>
    </cfoutput>
    
    <h2>3. String Functions</h2>
    <cfset myString = "  Hello World  ">
    <cfoutput>
        <div class="test pass">
            Original: "#myString#"<br>
            Trim: "#trim(myString)#"<br>
            UCase: "#uCase(myString)#"<br>
            LCase: "#lCase(myString)#"<br>
            Len: #len(trim(myString))#<br>
            Left(5): "#left(trim(myString), 5)#"<br>
            Right(5): "#right(trim(myString), 5)#"<br>
            Mid(7,5): "#mid(trim(myString), 7, 5)#"<br>
            Reverse: "#reverse(trim(myString))#"
        </div>
    </cfoutput>
    
    <h2>4. Conditional Logic</h2>
    <cfset score = 85>
    <cfoutput>
        <div class="test pass">
            Score: #score#<br>
            Grade: 
            <cfif score >= 90>
                A
            <cfelseif score >= 80>
                B
            <cfelseif score >= 70>
                C
            <cfelseif score >= 60>
                D
            <cfelse>
                F
            </cfif>
        </div>
    </cfoutput>
    
    <h2>5. Loop Constructs</h2>
    
    <h3>5.1 Index Loop</h3>
    <cfoutput>
        <div class="test pass">
            <cfloop from="1" to="5" index="i">
                Iteration #i#<br>
            </cfloop>
        </div>
    </cfoutput>
    
    <h3>5.2 List Loop</h3>
    <cfset myList = "apple,banana,cherry,date">
    <cfoutput>
        <div class="test pass">
            <cfloop list="#myList#" index="fruit">
                Fruit: #fruit#<br>
            </cfloop>
        </div>
    </cfoutput>
    
    <h3>5.3 Array Loop</h3>
    <cfset myArray = ["red", "green", "blue"]>
    <cfoutput>
        <div class="test pass">
            <cfloop array="#myArray#" index="i" item="color">
                Color ##i#: #color#<br>
            </cfloop>
        </div>
    </cfoutput>
    
    <h2>6. Array Operations</h2>
    <cfset colors = arrayNew(1)>
    <cfset arrayAppend(colors, "red")>
    <cfset arrayAppend(colors, "green")>
    <cfset arrayAppend(colors, "blue")>
    <cfoutput>
        <div class="test pass">
            Array length: #arrayLen(colors)#<br>
            First element: #colors[1]#<br>
            Is Array: #isArray(colors)#
        </div>
    </cfoutput>
    
    <h2>7. Struct Operations</h2>
    <cfset person = structNew()>
    <cfset person.name = "John Doe">
    <cfset person.age = 30>
    <cfset person.city = "New York">
    <cfoutput>
        <div class="test pass">
            Name: #person.name#<br>
            Age: #person.age#<br>
            City: #person.city#<br>
            Key Count: #structCount(person)#<br>
            Is Struct: #isStruct(person)#
        </div>
    </cfoutput>
    
    <h2>8. Date/Time Functions</h2>
    <cfset today = now()>
    <cfoutput>
        <div class="test pass">
            Current Time: #today#<br>
            Year: #year(today)#<br>
            Month: #month(today)#<br>
            Day: #day(today)#<br>
            Hour: #hour(today)#<br>
            Minute: #minute(today)#<br>
            Day of Week: #dayOfWeek(today)#
        </div>
    </cfoutput>
    
    <h2>9. Math Functions</h2>
    <cfoutput>
        <div class="test pass">
            Abs(-5): #abs(-5)#<br>
            Ceiling(4.3): #ceiling(4.3)#<br>
            Floor(4.7): #floor(4.7)#<br>
            Round(4.5): #round(4.5)#<br>
            Sqr(16): #sqr(16)#<br>
            Max(10, 20): #max(10, 20)#<br>
            Min(10, 20): #min(10, 20)#<br>
            Pi: #pi()#
        </div>
    </cfoutput>
    
    <h2>10. Decision Functions</h2>
    <cfset testNum = "123">
    <cfset testNull = "">
    <cfoutput>
        <div class="test pass">
            isNumeric("123"): #isNumeric(testNum)#<br>
            isNumeric("abc"): #isNumeric("abc")#<br>
            isEmpty(""): #isEmpty(testNull)#<br>
            isBoolean("true"): #isBoolean("true")#<br>
            isArray(colors): #isArray(colors)#<br>
            isStruct(person): #isStruct(person)#
        </div>
    </cfoutput>
    
    <h2>11. User-Defined Functions</h2>
    <cffunction name="greet" returntype="string">
        <cfargument name="name" type="string" required="true">
        <cfargument name="greeting" type="string" default="Hello">
        <cfreturn "#arguments.greeting#, #arguments.name#!">
    </cffunction>
    
    <cfoutput>
        <div class="test pass">
            greet("World"): #greet("World")#<br>
            greet("User", "Hi"): #greet("User", "Hi")#
        </div>
    </cfoutput>
    
    <h2>12. CGI Variables</h2>
    <cfoutput>
        <div class="test pass">
            Server Name: #cgi.server_name#<br>
            Request Method: #cgi.request_method#<br>
            Request URI: #cgi.request_uri#<br>
            Query String: #cgi.query_string#<br>
            Remote Address: #cgi.remote_addr#
        </div>
    </cfoutput>
    
    <h2>13. URL Parameters</h2>
    <cfoutput>
        <div class="test pass">
            <cfif isDefined("url.test")>
                URL.test = #url.test#
            <cfelse>
                No URL parameters. Try adding ?test=hello to the URL.
            </cfif>
        </div>
    </cfoutput>
    
    <h2>14. cfparam</h2>
    <cfparam name="myParam" default="default value">
    <cfoutput>
        <div class="test pass">
            myParam: #myParam#
        </div>
    </cfoutput>
    
    <h2>15. cfsavecontent</h2>
    <cfsavecontent variable="capturedContent">
        <p>This content was captured using cfsavecontent.</p>
        <ul>
            <li>Item 1</li>
            <li>Item 2</li>
            <li>Item 3</li>
        </ul>
    </cfsavecontent>
    <cfoutput>
        <div class="test pass">
            Captured content length: #len(capturedContent)# characters<br>
            Content:<br>
            #capturedContent#
        </div>
    </cfoutput>
    
    <h2>16. Hash Function</h2>
    <cfset password = "secret123">
    <cfoutput>
        <div class="test pass">
            MD5 Hash of "secret123": #hash(password)#
        </div>
    </cfoutput>
    
    <h2>17. UUID Generation</h2>
    <cfoutput>
        <div class="test pass">
            Generated UUID: #createUUID()#
        </div>
    </cfoutput>
    
    <hr>
    <p><strong>Test completed at #dateFormat(now(), "yyyy-mm-dd")# #timeFormat(now(), "HH:mm:ss")#</strong></p>
</body>
</html>
