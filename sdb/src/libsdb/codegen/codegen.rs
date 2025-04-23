use std::{fs, path::Path};

use core::mem::offset_of;
use libc::user;
use nix::libc;
use proc_macro::TokenStream;
use proc_macro2::Ident;
use quote::{format_ident, quote};
use regex::Regex;
use syn::LitStr;

#[proc_macro]
pub fn generate_registers(input: TokenStream) -> TokenStream {
    let arg = syn::parse_macro_input!(input as LitStr);
    let file_path = arg.value();
    let path = std::env::current_dir().unwrap();
    let current_path = path.to_str().unwrap();
    let content = fs::read_to_string(Path::new(&file_path))
        .unwrap_or_else(|_| panic!("{current_path}, cannot read {file_path}"));

    let mut variants = Vec::new();
    let mut infos = Vec::new();

    let mut push = |name: Ident,
                    dwarf_id: proc_macro2::TokenStream,
                    size_expr: proc_macro2::TokenStream,
                    offset_expr: proc_macro2::TokenStream,
                    typ: proc_macro2::TokenStream,
                    fmt: proc_macro2::TokenStream| {
        variants.push(quote! { #name });
        infos.push(quote! {
            RegisterInfo {
                id: RegisterId::#name,
                name: stringify!(#name),
                dwarf_id: #dwarf_id,
                size: #size_expr,
                offset: #offset_expr,
                type_: #typ,
                format: #fmt,
            }
        });
    };

    let re = Regex::new(r"DEFINE_GPR_64\((.+?),(.+?)\)").unwrap();
    for cap in re.captures_iter(&content) {
        let name = cap[1].trim();
        let dwarf_id = cap[2].trim().parse::<i32>().unwrap();
        let ident = format_ident!("{name}");
        push(
            ident.clone(),
            quote! {#dwarf_id},
            quote!(8),
            quote!(gpr_offset!(#ident)),
            quote!(RegisterType::Gpr),
            quote!(RegisterFormat::Uint),
        );
    }

    let re = Regex::new(r"DEFINE_GPR_32\((.+?),(.+?)\)").expect("regex compilation failed");
    for cap in re.captures_iter(&content) {
        let name = cap.get(1).unwrap().as_str().trim();
        let super_ = cap.get(2).unwrap().as_str().trim();
        let ident = format_ident!("{super_}");
        push(
            format_ident!("{name}"),
            quote! {-1},
            quote! {4},
            quote!(gpr_offset!(#ident)),
            quote!(RegisterType::SubGpr),
            quote!(RegisterFormat::Uint),
        );
    }

    let re = Regex::new(r"DEFINE_GPR_16\((.+?),(.+?)\)").expect("regex compilation failed");
    for cap in re.captures_iter(&content) {
        let name = cap.get(1).unwrap().as_str().trim();
        let super_ = cap.get(2).unwrap().as_str().trim();
        let ident = format_ident!("{super_}");
        push(
            format_ident!("{name}"),
            quote! {-1},
            quote! {2},
            quote!(gpr_offset!(#ident)),
            quote!(RegisterType::SubGpr),
            quote!(RegisterFormat::Uint),
        );
    }

    let re = Regex::new(r"DEFINE_GPR_8H\((.+?),(.+?)\)").expect("regex compilation failed");
    for cap in re.captures_iter(&content) {
        let name = cap.get(1).unwrap().as_str().trim();
        let super_ = cap.get(2).unwrap().as_str().trim();
        let ident = format_ident!("{super_}");
        push(
            format_ident!("{name}"),
            quote! {-1},
            quote! {1},
            quote!(gpr_offset!(#ident) + 1),
            quote!(RegisterType::SubGpr),
            quote!(RegisterFormat::Uint),
        );
    }

    let re = Regex::new(r"DEFINE_GPR_8L\((.+?),(.+?)\)").expect("regex compilation failed");
    for cap in re.captures_iter(&content) {
        let name = cap.get(1).unwrap().as_str().trim();
        let super_ = cap.get(2).unwrap().as_str().trim();
        let ident = format_ident!("{super_}");
        push(
            format_ident!("{name}"),
            quote! {-1},
            quote! {1},
            quote!(gpr_offset!(#ident)),
            quote!(RegisterType::SubGpr),
            quote!(RegisterFormat::Uint),
        );
    }

    let re = Regex::new(r"DEFINE_FPR\((.+?),(.+?),(.+?)\)").expect("regex compilation failed");
    for cap in re.captures_iter(&content) {
        let name = cap.get(1).unwrap().as_str().trim();
        let dwarf_id = cap.get(2).unwrap().as_str().trim().parse::<i32>().unwrap();
        let user_name = cap.get(3).unwrap().as_str().trim();
        let ident = format_ident!("{user_name}");
        push(
            format_ident!("{name}"),
            quote! {#dwarf_id},
            quote!(fpr_size!(#ident)),
            quote!(fpr_offset!(#ident)),
            quote!(RegisterType::Fpr),
            quote!(RegisterFormat::Uint),
        );
    }

    let re = Regex::new(r"DEFINE_FP_ST\((.+?)\)").expect("regex compilation failed");
    for cap in re.captures_iter(&content) {
        let number = cap
            .get(1)
            .unwrap()
            .as_str()
            .trim()
            .parse::<usize>()
            .unwrap();
        let number_i32 = cap.get(1).unwrap().as_str().trim().parse::<i32>().unwrap();
        let name = Box::leak(Box::new(format!("st{number}")));
        let name = name.as_str();
        push(
            format_ident!("{name}"),
            quote! {33+#number_i32},
            quote! {16},
            quote!(fpr_offset!(st_space)+#number*16),
            quote!(RegisterType::Fpr),
            quote!(RegisterFormat::LongDouble),
        );
    }

    let re = Regex::new(r"DEFINE_FP_MM\((.+?)\)").expect("regex compilation failed");
    for cap in re.captures_iter(&content) {
        let number = cap
            .get(1)
            .unwrap()
            .as_str()
            .trim()
            .parse::<usize>()
            .unwrap();
        let number_i32 = cap.get(1).unwrap().as_str().trim().parse::<i32>().unwrap();
        push(
            format_ident!("mm{number}"),
            quote! {41+#number_i32},
            quote! {8},
            quote!(fpr_offset!(st_space)+#number*16),
            quote!(RegisterType::Fpr),
            quote!(RegisterFormat::Vector),
        );
    }

    let re = Regex::new(r"DEFINE_FP_XMM\((.+?)\)").expect("regex compilation failed");
    for cap in re.captures_iter(&content) {
        let number = cap
            .get(1)
            .unwrap()
            .as_str()
            .trim()
            .parse::<usize>()
            .unwrap();
        let number_i32 = cap.get(1).unwrap().as_str().trim().parse::<i32>().unwrap();
        push(
            format_ident!("xmm{number}"),
            quote! {17+#number_i32},
            quote! {16},
            quote!(fpr_offset!(xmm_space)+#number*16),
            quote!(RegisterType::Fpr),
            quote!(RegisterFormat::Vector),
        );
    }

    let re = Regex::new(r"DEFINE_DR\((.+?)\)").expect("regex compilation failed");
    for cap in re.captures_iter(&content) {
        let number = cap.get(1).unwrap().as_str().trim();
        let num = number.parse::<usize>().unwrap();
        let offset = offset_of!(user, u_debugreg) + num * 8;
        push(
            format_ident!("dr{number}"),
            quote! {-1},
            quote! {8},
            quote!(#offset),
            quote!(RegisterType::Dr),
            quote!(RegisterFormat::Uint),
        );
    }

    let expanded = quote! {
        #[derive(Debug, Clone, Copy, Eq, PartialEq, TryFromPrimitive)]
        #[repr(i32)]
        pub enum RegisterId { #( #variants, )* }

        pub static GRegisterInfos: &[RegisterInfo] = &[
            #( #infos, )*
        ];
    };
    TokenStream::from(expanded)
}
