using System;
using System.Runtime.CompilerServices;

namespace libdebug {

    public partial class PS4DBG {

        /// <summary>
        /// Print's message in following format: From [Name of the Function from where this is used in]() - [Message Here]
        /// </summary>
        public static void DebugPrint(string message, [CallerMemberName] string callerName = "") 
            => Console.WriteLine($"From {callerName}() - {message}");
        
        /// <summary>
        /// Print's warning in following format: WARNING! In [Function Name]() - [Message here]
        /// </summary>
        public static void DebugPrintWarning(string message, [CallerMemberName] string callerName = "")
            => Console.WriteLine($"WARNING! In {callerName}() - {message}");
        
    }
}