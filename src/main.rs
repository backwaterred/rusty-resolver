use clap::{ load_yaml };

mod dns;
mod parser;
mod resolver;

fn main() -> Result<(), Box<dyn std::error::Error>>
{

    let yaml = load_yaml!("clap.yml");
    let ms = clap::App::from_yaml(yaml).get_matches();

    let hostname = ms.value_of("lookup").expect("Error unwrapping a required value");
    println!("Performing lookup for: {}", hostname);

    let addr = resolver::resolve(&hostname)?;
    println!("Found record {}", addr);

    Ok(())
}
