use std::{env};
use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::str::FromStr;
use std::time::Duration;
use std::collections::HashMap;
use surge_ping::{Client, Config, PingIdentifier, PingSequence};
use std::string::ToString;
use tokio::time::timeout;
use tokio::task;
use crate::ports::PORTS;

mod ports;

#[derive(Clone)]
struct ConfigConnection {
    ip: IpAddr,
    subnet: Option<Subnet>,
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
    ip: Ipv4Addr,
    open_ports: Vec<u16>,
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();

    let config = ConfigConnection::build(args.clone()).unwrap();

    if let Some(_) = config.subnet {
        show_summary_sweep(sweep(config).await);
    } else {
        println!("{:?}", scan_ip(Ipv4Addr::from_str(config.ip.to_string().as_str()).unwrap(), config.get_port()).open_ports);
    }
}

async fn sweep(config: ConfigConnection) -> ResultsSweep{
    let mut ip_map: HashMap<Ipv4Addr, Vec<u16>> = HashMap::new();

    let subnet = config.clone().subnet.unwrap();

    let mut hosts: Vec<Ipv4Addr> = Vec::new();

    let mut handles = Vec::new();
    let mut nets: Vec<Subnet> = Vec::new();

    let step = 64; // Lower the step, the faster but more resource intensive the program will be

    println!("Beginning sweep of {} hosts", subnet.max_hosts);

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

    println!("Ping scan complete, found {} alive hosts, beginning port scan of each.", hosts.len());

    let mut handles_scan = Vec::new();

    let mut hosts_mod = hosts.clone();

    let host_step = 4; // Higher the number, faster but more resource intensive program will be

    let port = config.clone().get_port();

    for _ in 0..host_step {
        hosts_mod = hosts_mod.split_off(hosts.len() / host_step);
        for host in hosts_mod.clone() {
            handles_scan.push(task::spawn(async move {
                scan_ip(host, port)
            }))
        }
    }

    for handle in handles_scan {
        let result = handle.await.unwrap();
        ip_map.insert(result.ip, result.open_ports);
    }


    ResultsSweep { ip_map, alive_hosts: hosts }
}

fn show_summary_sweep(results: ResultsSweep) {
    println!("Scan results: ");
    println!("======================");
    for host in results.alive_hosts {
        println!("Scan report for {host}\nHost is up");
        if let Some(ports_open) = results.ip_map.get(&host) {
            if ports_open.is_empty() {
                println!("All 1000 TCP ports closed.");
            }
            for port in ports_open {
                println!("PORT      STATE       SERVICE");
                println!("{port}/tcp  open         {:?}", PORTS.get(port));
            }
        } else {
            println!("All 1000 TCP ports closed.");
        }
        println!();
    }
}

async fn get_alive_hosts(hosts: usize, ip_init: Ipv4Addr) -> Vec<Ipv4Addr> {
    let mut alive_hosts: Vec<Ipv4Addr> = Vec::new();

    let mut ip = ip_init;

    for _ in 0..hosts {
        if let Ok(_) = host_up(ip).await {
            alive_hosts.push(ip);
        }
        ip = Ipv4Addr::from_bits(ip.to_bits() + 1);
    }
    alive_hosts
}


async fn host_up(ip: Ipv4Addr) -> Result<(), Box<dyn Error>> {

    let client = Client::new(&Config::default())?;

    let mut pinger = client.pinger(IpAddr::from(ip), PingIdentifier(0)).await;
    pinger.timeout(Duration::from_millis(200));

    match timeout(Duration::from_millis(200), pinger.ping(PingSequence(0), &[0])).await {
        Ok(Ok((_, _))) => {
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
            octet = i - 1;
            break;
        }
    }
    let mut ip_start = String::new();

    for i in 0..4 {
        let step = 2_usize.pow((32 - cidr) as u32) / 256;
        let oct = str::parse::<i32>(ip.octets().get(i).unwrap().to_string().as_str()).unwrap();
        if i < octet {
            ip_start += oct.to_string().as_str();
            ip_start += ".";
        } else if i == octet {
            for k in 0..(256 / step) {
                if k * step > oct as usize {
                    ip_start += ((k - 1) * step).to_string().as_str();
                    break;
                }
            }
        } else {
            ip_start += ".0";
        }
    }

    Ipv4Addr::from_str(ip_start.as_str()).unwrap()
}

fn scan_ip(ip: Ipv4Addr, port: Option<usize>) -> ResultsSingle {
    let mut open_ports: Vec<u16> = Vec::new();
    let mut port_range = (0, 1023);
    if let Some(po) = port {
        port_range = (po, po + 1);
    }
    let mut socket = SocketAddr::new(IpAddr::from(ip), port_range.0 as u16);


    for p in port_range.0..port_range.1 {
        socket.set_port(p as u16);
        if let Ok(_stream) = TcpStream::connect_timeout(&socket, Duration::new(0, 200)) {
            open_ports.push(p as u16);
        }
    }
    ResultsSingle { ip, open_ports }

}

impl ConfigConnection {
    fn build(args: Vec<String>) -> Result<Self, Box<dyn Error>> {
        if args.len() < 2 {
            return Ok(ConfigConnection { ip: IpAddr::from_str("127.0.0.1")?, subnet: None, options: vec![] })
        }

        if args.get(1).unwrap().contains("/") {
            let mut arg_itr = args.get(1).unwrap().split("/");

            let ip_str = arg_itr.clone().next().unwrap();

            arg_itr.next();

            let cidr = arg_itr.clone().next().unwrap().parse::<usize>()?;

            let subnet = Subnet { first_ip: find_ip_start(Ipv4Addr::from_str(ip_str)?, cidr), max_hosts: 2_usize.pow((32 - cidr) as u32) };

            return Ok(ConfigConnection { ip: IpAddr::from_str(ip_str)?, subnet: Some(subnet), options: args.clone().split_off(2) });

        }

        Ok(ConfigConnection { ip: IpAddr::from_str(args.get(1).unwrap())?, subnet: None, options: args.clone().split_off(2)})
    }

    fn get_port(&self) -> Option<usize> {
        if self.options.contains(&"-p".to_string()) {
            let idx = self.options.iter().position(|n| n == "-p").unwrap();
            return Some(str::parse::<usize>(self.options.get(idx + 1).unwrap()).unwrap());
        }

        None
    }
}