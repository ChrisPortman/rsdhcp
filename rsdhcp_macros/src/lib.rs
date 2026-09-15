use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::{ToTokens, quote};
use syn::{DeriveInput, parse_macro_input};

fn variant_code(variant: &syn::Variant) -> Option<u8> {
    for attr in &variant.attrs {
        if attr.path().is_ident("code")
            && let Ok(lit) = attr.parse_args::<syn::LitInt>()
            && let Ok(n) = lit.base10_parse::<u8>()
        {
            return Some(n);
        }
    }

    None
}

#[proc_macro_derive(DhcpOptions, attributes(code))]
pub fn dhcp_options(input: TokenStream) -> TokenStream {
    let ast: DeriveInput = parse_macro_input!(input as DeriveInput);
    let name = &ast.ident;
    let data = &ast.data;

    if let syn::Data::Enum(d) = &data {
        let mut variant_idents: Vec<syn::Ident> = vec![];
        for v in &d.variants {
            variant_idents.push(v.ident.clone())
        }

        let mut code_consts: Vec<TokenStream2> = vec![];
        let mut to_code_matches: Vec<TokenStream2> = vec![];
        let mut to_network_matches: Vec<TokenStream2> = vec![];
        let mut new_matches: Vec<TokenStream2> = vec![];

        for v in &d.variants {
            let ident = &v.ident;
            let vtype = match &v.fields {
                syn::Fields::Unnamed(f) => f.unnamed.first(),
                _ => None,
            };

            let ident_const =
                syn::Ident::new(ident.to_string().to_uppercase().as_str(), ident.span());

            if let Some(code) = variant_code(v) {
                code_consts.push(quote! {
                    pub const #ident_const: u8 = #code
                });

                match vtype {
                    Some(vt) => {
                        let vtype_field = vt.ty.to_token_stream();
                        new_matches.push(quote! {
                            #code => #name::#ident(<#vtype_field>::from_network(data)?)
                        });
                        to_code_matches.push(quote! {
                            Self::#ident(_) => #code
                        });
                        to_network_matches.push(quote! {
                            Self::#ident(o) => Some(o.to_network()),
                        });
                    }
                    None => {
                        new_matches.push(quote! {
                            #code => #name::#ident
                        });
                        to_code_matches.push(quote! {
                            Self::#ident => #code
                        });
                        to_network_matches.push(quote! {
                            Self::#ident => None,
                        });
                    }
                };
            }
        }

        let expanded = quote! {
            impl #name {
                #(#code_consts;)*

                pub fn new(code: &u8, data: &[u8]) -> Result<Self, PacketError> {
                    let opt = match code {
                        #(#new_matches,)*
                        _ => { return Err(PacketError::new(format!("Unknown code: {}", code).as_str())) },
                    };
                    Ok(opt)
                }

                pub fn code(&self) -> u8 {
                    match *self {
                        #(#to_code_matches),*
                    }
                }

                pub fn to_network(&self) -> Vec<u8> {
                    let mut bytes: Option<Vec<u8>> = match self {
                        #(#to_network_matches)*
                    };

                    let result = match bytes {
                        Some(mut b) => {
                            let mut r: Vec<u8> = vec![self.code(), b.len() as u8];
                            r.append(&mut b);
                            r
                        },
                        None => vec![self.code()],
                    };

                    result
                }

                pub fn from_network(data: &[u8]) -> Result<Self, PacketError> {
                    if data.len() < 1 {
                        return Err(PacketError::new("Malformed Option"));
                    }

                    let code = data[0];
                    match code {
                        0 => return Self::new(&code, &[]),
                        255 => return Self::new(&code, &[]),
                        _ => {},
                    };

                    if data.len() < 2 {
                        return Err(PacketError::new("Malformed Option"));
                    }

                    let len = data[1] as usize;
                    let end = 2 + len;

                    if data.len() < end {
                        return Err(PacketError::new("Malformed Option"));
                    }

                    Self::new(&code, &data[2..end])
                }
            }
        };
        return TokenStream::from(expanded);
    };
    panic!("DhcpOptions must be an enum");
}
