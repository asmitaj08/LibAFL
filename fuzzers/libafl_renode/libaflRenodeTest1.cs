// <auto-generated>
// This code is generated by csbindgen.
// DON'T CHANGE THIS DIRECTLY.
// </auto-generated>
#pragma warning disable CS8500
#pragma warning disable CS8981
using System;
using System.Runtime.InteropServices;


namespace CsBindgen
{
    internal static unsafe partial class NativeMethods
    {
        const string __DllName = "liabaflTestlib";



        [DllImport(__DllName, EntryPoint = "get_cov_map_ptr", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        public static extern byte* get_cov_map_ptr();

        [DllImport(__DllName, EntryPoint = "external_current_millis2", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        public static extern ulong external_current_millis2();

        [DllImport(__DllName, EntryPoint = "main_fuzzing_func", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        public static extern void main_fuzzing_func(byte* input_dir, delegate* unmanaged[Cdecl]<byte*, void> harness_fn);


    }



}
    