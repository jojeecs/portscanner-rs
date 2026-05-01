use crate::thread::spawn;
use std::{env, thread};
use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::str::FromStr;
use std::time::Duration;
use std::collections::HashMap;
use std::ops::Sub;
use surge_ping::{Client, Config, PingIdentifier, PingSequence};
use std::string::ToString;
use tokio::time::timeout;
use tokio::task;
use crate::ports::PORTS;

mod ports;

#[derive(Clone)]
struct ConfigCust {
    ip: IpAddr,
    subnet: Option<Subnet>,
    cidr: usize,
    options: Vec<String>,
}

#[derive(Clone, Debug)]
struct Subnet {
    first_ip: Ipv4Addr,
    max_hosts: usize,
}

struct ResultsSweep {
    ip_map: HashMap<Ipv4Addr, Vec<u16>>,
    alive_hosts: Vec<Ipv4Addr>,
}

struct ResultsSingle {
    is_up: bool,
    open_ports: Vec<u16>,
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();

    let config = ConfigCust::build(args.clone()).unwrap();

    if let Some(_) = config.subnet {
        show_summary_sweep(sweep(config).await);
    } else {
        println!("{:?}", scan_ip(Ipv4Addr::from_str(config.ip.to_string().as_str()).unwrap(), config.get_port()).open_ports);
    }
}

async fn sweep(config: ConfigCust) -> ResultsSweep{

    let mut ip_map: HashMap<Ipv4Addr, Vec<u16>> = HashMap::new();

    let subnet = config.clone().subnet.unwrap();

    let mut hosts: Vec<Ipv4Addr> = Vec::new();


    let mut handles = Vec::new();
    let mut nets: Vec<Subnet> = Vec::new();

    let mut step = 512;

    for _ in 0..subnet.clone().max_hosts / step {
        nets.push(subnet.clone());
    }

    for (i, net) in nets.into_iter().enumerate() {
        let ip = Ipv4Addr::from_bits(net.first_ip.to_bits() + (i as u32 * step as u32));

        handles.push(task::spawn(async move {
            get_alive_hosts(step.clone(), ip).await
        }));
    }

    for handle in handles {
        let mut result = handle.await.unwrap();
        hosts.append(&mut result);

    }

    let port = config.clone().get_port();

    for host in hosts.clone() {
        let results = scan_ip(host, port);
        ip_map.insert(host, results.open_ports);
    }


    ResultsSweep { ip_map, alive_hosts: hosts }
}

fn show_summary_sweep(results: ResultsSweep) {
    println!("Scan results: ");
    println!("======================");
    for ip in results.alive_hosts {
        println!("Scan report for {ip}\nHost is up");
        if results.ip_map.contains_key(&ip) {
            for ports_open in results.ip_map.get(&ip) {
                for port in ports_open {
                    println!("PORT      STATE       SERVICE");
                    println!("{port}/tcp  open         {:?}", PORTS.get(port));
                }
            }
        }
        println!();
    }
}

async fn get_alive_hosts(hosts: usize, ip_init: Ipv4Addr) -> Vec<Ipv4Addr> {
    let mut alive_hosts: Vec<Ipv4Addr> = Vec::new();

    let mut ip = ip_init;

    for _ in 0..hosts {
        if let Ok(res) = host_up(ip).await {
            println!("Reply from {ip}");
            alive_hosts.push(ip);
        }
        ip = Ipv4Addr::from_bits(ip.to_bits() + 1);
    }
    alive_hosts
}


async fn host_up(ip: Ipv4Addr) -> Result<(), Box<dyn Error>> {

    let client = Client::new(&Config::default())?;

    let mut pinger = client.pinger(IpAddr::from(ip), PingIdentifier(0)).await;
    pinger.timeout(Duration::from_millis(25));

    match timeout(Duration::from_millis(25), pinger.ping(PingSequence(0), &[0])).await {
        Ok(Ok((packet, duration))) => {
            Ok(())
        }
        Ok(Err(e)) => {
            Err(Box::from(e))
        },
        Err(e) => {
            Err(Box::from(e))
        },
    }
}

fn find_ip_start(ip: Ipv4Addr, cidr: usize) -> Ipv4Addr {
    let mut octet = 1;
    for i in 1..=4 {
        if 8 * i >= cidr {
            octet = i;
            break;
        }
    }
    let as_ipv4 = Ipv4Addr::from_str(&*ip.to_string()).unwrap();
    let mut ip_start = String::new();

    for i in 0..4 {
        if octet == 4 {
            let step = 2_usize.pow((32 - cidr) as u32);
            for p in 1..(256 / step) {
                if *as_ipv4.octets().get(3).unwrap()  < (p * step) as u8 {
                    ip_start += as_ipv4.octets().get(0).unwrap().to_string().as_str();
                    ip_start += ".";
                    ip_start += as_ipv4.octets().get(1).unwrap().to_string().as_str();
                    ip_start += ".";
                    ip_start += as_ipv4.octets().get(1).unwrap().to_string().as_str();
                    ip_start += ".";
                    ip_start += (((p * step) - step) + 1).to_string().as_str();
                    return Ipv4Addr::from_str(ip_start.as_str()).unwrap();
                }
            }
        }

        if i < octet - 1 {
            ip_start += as_ipv4.octets().get(i).unwrap().to_string().as_str();
            if i != octet - 2 {
                ip_start += ".";
            }
        } else {
            ip_start += ".0";
        }
    }

    Ipv4Addr::from_str(ip_start.as_str()).unwrap()
}

fn scan_ip(ip: Ipv4Addr, port: Option<usize>) -> ResultsSingle {
    let mut open_ports: Vec<u16> = Vec::new();
    let mut port_range = (0, 100);
    if let Some(po) = port {
        port_range = (po, po + 1);
    }
    let mut socket = SocketAddr::new(IpAddr::from(ip), port_range.0 as u16);


    for p in port_range.0..port_range.1 {
        socket.set_port(p as u16);
        if let Ok(stream) = TcpStream::connect_timeout(&socket, Duration::new(0, 200)) {
            open_ports.push(p as u16);
        }
    }
    ResultsSingle { is_up: true, open_ports }

}

impl ConfigCust {
    fn build(args: Vec<String>) -> Result<Self, Box<dyn Error>> {
        if args.len() < 2 {
            return Ok(ConfigCust { ip: IpAddr::from_str("127.0.0.1")?, subnet: None, cidr: 0, options: vec![] })
        }

        if args.get(1).unwrap().contains("/") {
            let mut arg_itr = args.get(1).unwrap().split("/");

            let ip_str = arg_itr.clone().next().unwrap();

            arg_itr.next();

            let cidr = arg_itr.clone().next().unwrap().parse::<usize>()?;

            let subnet = Subnet { first_ip: find_ip_start(Ipv4Addr::from_str(ip_str)?, cidr), max_hosts: 2_usize.pow((32 - cidr) as u32) };

            return Ok(ConfigCust { ip: IpAddr::from_str(ip_str)?, subnet: Some(subnet), cidr, options: args.clone().split_off(2) });

        }

        Ok(ConfigCust { ip: IpAddr::from_str(args.get(1).unwrap())?, subnet: None, cidr: 0, options: args.clone().split_off(2)})
    }

    fn get_port(&self) -> Option<usize> {
        if self.options.contains(&"-p".to_string()) {
            let idx = self.options.iter().position(|n| n == "-p").unwrap();
            return Some(str::parse::<usize>(self.options.get(idx + 1).unwrap()).unwrap());
        }

        None
    }
}