// Copyright 2022, The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use proc_macro2::TokenStream;
use quote::{format_ident, quote, quote_spanned};
use syn::{
    parse_macro_input, parse_quote, spanned::Spanned, Data, DeriveInput, Fields, GenericParam,
    Generics, Ident, Index,
};

#[proc_macro_derive(AsCborValue)]
pub fn derive_as_cbor_value(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    derive_as_cbor_value_internal(&input)
}

fn derive_as_cbor_value_internal(input: &DeriveInput) -> proc_macro::TokenStream {
    let name = &input.ident;

    let generics = add_trait_bounds(&input.generics);
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    let from_val = from_val_struct(&input.data);
    let to_val = to_val_struct(&input.data);
    let cddl = cddl_struct(name, &input.data);

    let expanded = quote! {

        impl #impl_generics AsCborValue for #name #ty_generics #where_clause {
            fn from_cbor_value(value: ciborium::value::Value) -> Result<Self, CborError> {
                #from_val
            }
            fn to_cbor_value(self) -> Result<ciborium::value::Value, CborError> {
                #to_val
            }
            fn cddl_typename() -> Option<String> {
                Some(stringify!(#name).to_string())
            }
            fn cddl_schema() -> Option<String> {
                #cddl
            }
        }
    };

    expanded.into()
}

fn add_trait_bounds(generics: &Generics) -> Generics {
    let mut generics = generics.clone();
    for param in &mut generics.params {
        if let GenericParam::Type(ref mut type_param) = *param {
            type_param.bounds.push(parse_quote!(AsCborValue));
        }
    }
    generics
}

fn to_val_struct(data: &Data) -> TokenStream {
    match *data {
        Data::Struct(ref data) => match data.fields {
            Fields::Named(ref fields) => {
                let nfields = fields.named.len();
                let recurse = fields.named.iter().map(|f| {
                    let name = &f.ident;
                    quote_spanned! {f.span()=>
                        v.push(AsCborValue::to_cbor_value(self.#name)?)
                    }
                });
                quote! {
                    {
                        let mut v = Vec::new();
                        v.try_reserve(#nfields).map_err(|_e| CborError::AllocationFailed)?;
                        #(#recurse; )*
                        Ok(ciborium::value::Value::Array(v))
                    }
                }
            }
            Fields::Unnamed(ref fields) if fields.unnamed.len() == 1 => {
                quote! {
                    self.0.to_cbor_value()
                }
            }
            Fields::Unnamed(ref fields) => {
                let nfields = fields.unnamed.len();
                let recurse = fields.unnamed.iter().enumerate().map(|(i, f)| {
                    let index = Index::from(i);
                    quote_spanned! {f.span()=>
                        v.push(AsCborValue::to_cbor_value(self.#index)?)
                    }
                });
                quote! {
                    {
                        let mut v = Vec::new();
                        v.try_reserve(#nfields).map_err(|_e| CborError::AllocationFailed)?;
                        #(#recurse; )*
                        Ok(ciborium::value::Value::Array(v))
                    }
                }
            }
            Fields::Unit => unimplemented!(),
        },
        Data::Enum(_) => {
            quote! {
                let v: ciborium::value::Integer = (self as i32).into();
                Ok(ciborium::value::Value::Integer(v))
            }
        }
        Data::Union(_) => unimplemented!(),
    }
}

fn from_val_struct(data: &Data) -> TokenStream {
    match data {
        Data::Struct(ref data) => match data.fields {
            Fields::Named(ref fields) => {
                let nfields = fields.named.len();
                let recurse = fields.named.iter().enumerate().rev().map(|(i, f)| {
                    let name = &f.ident;
                    let index = Index::from(i);
                    let typ = &f.ty;
                    quote_spanned! {f.span()=>
                                    #name: <#typ>::from_cbor_value(a.remove(#index))?
                    }
                });
                quote! {
                    let mut a = match value {
                        ciborium::value::Value::Array(a) => a,
                        _ => return cbor_type_error(&value, "arr"),
                    };
                    if a.len() != #nfields {
                        return Err(CborError::UnexpectedItem(
                            "arr",
                            concat!("arr len ", stringify!(#nfields)),
                        ));
                    }

                    Ok(Self {
                        #(#recurse, )*
                    })
                }
            }
            Fields::Unnamed(ref fields) if fields.unnamed.len() == 1 => {
                let inner = fields.unnamed.first().unwrap();
                let typ = &inner.ty;
                quote! {
                    Ok(Self(<#typ>::from_cbor_value(value)?))
                }
            }
            Fields::Unnamed(ref fields) => {
                let nfields = fields.unnamed.len();
                let recurse1 = fields.unnamed.iter().enumerate().rev().map(|(i, f)| {
                    let typ = &f.ty;
                    let varname = format_ident!("field_{}", i);
                    quote_spanned! {f.span()=>
                                    let #varname = <#typ>::from_cbor_value(a.remove(#i))?;
                    }
                });
                let recurse2 = fields.unnamed.iter().enumerate().map(|(i, f)| {
                    let varname = format_ident!("field_{}", i);
                    quote_spanned! {f.span()=>
                                    #varname
                    }
                });
                quote! {
                    let mut a = match value {
                        ciborium::value::Value::Array(a) => a,
                        _ => return cbor_type_error(&value, "arr"),
                    };
                    if a.len() != #nfields {
                        return Err(CborError::UnexpectedItem("arr",
                                                             concat!("arr len ",
                                                                     stringify!(#nfields))));
                    }

                    #(#recurse1)*

                    Ok(Self( #(#recurse2, )* ))
                }
            }
            Fields::Unit => unimplemented!(),
        },
        Data::Enum(enum_data) => {
            let recurse = enum_data.variants.iter().map(|variant| {
                let vname = &variant.ident;
                quote_spanned! {variant.span()=>
                                x if x == Self::#vname as i32 => Ok(Self::#vname),
                }
            });

            quote! {
                use core::convert::TryInto;

                let v: i32 = match value {
                    ciborium::value::Value::Integer(i) => i.try_into().map_err(|_| {
                        CborError::OutOfRangeIntegerValue
                    })?,
                    v => return cbor_type_error(&v, &"int"),
                };

                match v {
                    #(#recurse)*
                    _ => Err(
                        CborError::OutOfRangeIntegerValue
                    ),
                }
            }
        }
        Data::Union(_) => unimplemented!(),
    }
}

fn cddl_struct(name: &Ident, data: &Data) -> TokenStream {
    match *data {
        Data::Struct(ref data) => match data.fields {
            Fields::Named(ref fields) => {
                if fields.named.iter().next().is_none() {
                    return quote! {
                        Some(format!("[]"))
                    };
                }

                let fmt_recurse = fields.named.iter().map(|f| {
                    let name = &f.ident;
                    quote_spanned! {f.span()=>
                                    concat!("    ", stringify!(#name), ": {},\n")
                    }
                });
                let fmt = quote! {
                    concat!("[\n",
                            #(#fmt_recurse, )*
                            "]")
                };
                let recurse = fields.named.iter().map(|f| {
                    let typ = &f.ty;
                    quote_spanned! {f.span()=>
                                    <#typ>::cddl_ref()
                    }
                });
                quote! {
                    Some(format!(
                        #fmt,
                        #(#recurse, )*
                    ))
                }
            }
            Fields::Unnamed(ref fields) if fields.unnamed.len() == 1 => {
                let inner = fields.unnamed.first().unwrap();
                let typ = &inner.ty;
                quote! {
                    Some(<#typ>::cddl_ref())
                }
            }
            Fields::Unnamed(ref fields) => {
                if fields.unnamed.iter().next().is_none() {
                    return quote! {
                        Some(format!("()"))
                    };
                }

                let fmt_recurse = fields.unnamed.iter().map(|f| {
                    quote_spanned! {f.span()=>
                                    "    {},\n"
                    }
                });
                let fmt = quote! {
                    concat!("[\n",
                             #(#fmt_recurse, )*
                             "]")
                };
                let recurse = fields.unnamed.iter().map(|f| {
                    let typ = &f.ty;
                    quote_spanned! {f.span()=>
                                    <#typ>::cddl_ref()
                    }
                });
                quote! {
                    Some(format!(
                        #fmt,
                        #(#recurse, )*
                    ))
                }
            }
            Fields::Unit => unimplemented!(),
        },
        Data::Enum(ref enum_data) => {
            let fmt_recurse = enum_data.variants.iter().map(|variant| {
                let vname = &variant.ident;
                quote_spanned! {variant.span()=>
                                concat!("    ",
                                        stringify!(#name),
                                        "_",
                                        stringify!(#vname),
                                        ": {},\n")
                }
            });
            let fmt = quote! {
                concat!("&(\n",
                         #(#fmt_recurse, )*
                         ")")
            };
            let recurse = enum_data.variants.iter().map(|variant| {
                let vname = &variant.ident;
                quote_spanned! {variant.span()=>
                                Self::#vname as i32
                }
            });
            quote! {
                Some(format!(
                    #fmt,
                    #(#recurse, )*
                ))
            }
        }
        Data::Union(_) => unimplemented!(),
    }
}

#[proc_macro_derive(FromRawTag)]
pub fn derive_from_raw_tag(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    derive_from_raw_tag_internal(&input)
}

fn derive_from_raw_tag_internal(input: &DeriveInput) -> proc_macro::TokenStream {
    let name = &input.ident;
    let from_val = from_raw_tag(name, &input.data);
    let expanded = quote! {
        pub fn from_raw_tag_value(raw_tag: u32) -> #name {
            #from_val
        }
    };
    expanded.into()
}

fn from_raw_tag(name: &Ident, data: &Data) -> TokenStream {
    match data {
        Data::Enum(enum_data) => {
            let recurse = enum_data.variants.iter().map(|variant| {
                let vname = &variant.ident;
                quote_spanned! {variant.span()=>
                                x if x == raw_tag_value(#name::#vname) => #name::#vname,
                }
            });

            quote! {
                match raw_tag {
                    #(#recurse)*
                    _ => #name::Invalid,
                }
            }
        }
        _ => unimplemented!(),
    }
}

#[proc_macro_derive(LegacySerialize)]
pub fn derive_legacy_serialize(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    derive_legacy_serialize_internal(&input)
}

fn derive_legacy_serialize_internal(input: &DeriveInput) -> proc_macro::TokenStream {
    let name = &input.ident;

    let deserialize_val = deserialize_struct(&input.data);
    let serialize_val = serialize_struct(&input.data);

    let expanded = quote! {
        impl InnerSerialize for #name {
            fn deserialize(data: &[u8]) -> Result<(Self, &[u8]), Error> {
                #deserialize_val
            }
            fn serialize_into(&self, buf: &mut Vec<u8>) -> Result<(), Error> {
                #serialize_val
            }
        }
    };

    expanded.into()
}

fn deserialize_struct(data: &Data) -> TokenStream {
    match data {
        Data::Struct(ref data) => match data.fields {
            Fields::Named(ref fields) => {
                let recurse1 = fields.named.iter().map(|f| {
                    let name = &f.ident;
                    let typ = &f.ty;
                    quote_spanned! {f.span()=>
                                    let (#name, data) = <#typ>::deserialize(data)?;
                    }
                });
                let recurse2 = fields.named.iter().map(|f| {
                    let name = &f.ident;
                    quote_spanned! {f.span()=>
                                    #name
                    }
                });
                quote! {
                    #(#recurse1)*
                    Ok((Self {
                        #(#recurse2, )*
                    }, data))
                }
            }
            Fields::Unnamed(_) => unimplemented!(),
            Fields::Unit => unimplemented!(),
        },
        Data::Enum(_) => unimplemented!(),
        Data::Union(_) => unimplemented!(),
    }
}

fn serialize_struct(data: &Data) -> TokenStream {
    match data {
        Data::Struct(ref data) => match data.fields {
            Fields::Named(ref fields) => {
                let recurse = fields.named.iter().map(|f| {
                    let name = &f.ident;
                    quote_spanned! {f.span()=>
                                    self.#name.serialize_into(buf)?;
                    }
                });
                quote! {
                    #(#recurse)*
                    Ok(())
                }
            }
            Fields::Unnamed(_) => unimplemented!(),
            Fields::Unit => unimplemented!(),
        },
        Data::Enum(_) => unimplemented!(),
        Data::Union(_) => unimplemented!(),
    }
}
