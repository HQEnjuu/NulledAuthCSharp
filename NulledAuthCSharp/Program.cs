using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NulledAuthCSharp
{
    internal class Program
    {
        static void Main(string[] args)
        {
            AuthHandler authHandler = new AuthHandler("NULLED-T1TTR-FMJ6C-WFSYL-W0NH4-HX0I9-TO", "1", 2, "test");
            authHandler.checkReg();

            authHandler.checkAuth();

            if (authHandler.canAuth())
            {
                Console.WriteLine("Access granted");
            }
            else
            {
                Console.WriteLine("Access denied");
            }
            Console.ReadKey();
        }
    }
}
