use std::{env};
use std::error::Error;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::collections::HashMap;
use surge_ping::{Client, Config, PingIdentifier, PingSequence};
use std::string::ToString;
use regex::Regex;
use tokio::task;
use tokio::net::TcpStream;
use crate::Argument::{AllOnline, OutputFile, PingScan, Port, Timing, Verbose, CIDR, IP};
use crate::ports::PORTS;

mod ports;

const TIMING_QUIET: &'static str = "T1";
const TIMING_NORMAL: &'static str = "T2";
const TIMING_LOUD: &'static str = "T3";
const TIMING_AGGRESSIVE: &'static str = "T4";
const TIMING_INSANE: &'static str = "T5";

#[derive(Clone, Debug)]
#[derive(PartialEq)]
enum Argument {
    IP(Ipv4Addr),
    CIDR(u32),
    Port(u32),
    Verbose,
    Timing(String),
    OutputFile(String),
    PingScan,
    AllOnline,
}

#[derive(Clone, Debug)]
struct Instance {
    options: Vec<Argument>,
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

#[derive(Clone, Debug)]
struct ResultsSingle {
    ip: Ipv4Addr,
    open_ports: Vec<u16>,
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();

    let config = Instance::build(args.clone()).unwrap();

    let start = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();

    if let Some(_) = config.options.iter().find(|x| {
        if let CIDR(_) = x {
            return true;
        }
        false
    }) {
        let results = sweep(config.clone()).await;
        if !config.options.contains(&Timing(TIMING_QUIET.to_string())) {
            show_summary_sweep(results, Some(config.get_port()));
        }
        let end = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        println!("Duration: {:?}", end - start);
    } else {
        
    }
}

fn parse_args(string_args: Vec<String>) -> Vec<Argument> {
    let mut args: Vec<Argument> = Vec::new();

    let mut iterator = string_args.iter().skip(1);



    while let Some(arg) = iterator.next() {
        if arg.eq("-p") || arg.eq("--port") {
            args.push(Port(str::parse::<u32>(iterator.next().expect("Invalid port number passed")).expect("Invalid port number passed")));
        }  else if arg.eq("-v") {
            args.push(Verbose);
        } else if arg.contains(&"-T".to_string()) {
            args.push(Timing(arg.to_string()));
        } else if arg.eq("-O") || arg.eq("--output") {
            args.push(OutputFile(arg.to_string()));
        } else if arg.eq("-sn") {
            args.push(PingScan);
        } else if arg.eq("-Pn") {
            args.push(AllOnline);
        } else if Regex::new(r"[(0-9)+].[(0-9)+].[(0-9)+].[(0-9)+]").unwrap().is_match(arg.as_str()) {
            if arg.contains("/") {
                let mut arg_itr = arg.split("/");

                let ip_str = arg_itr.clone().next().unwrap();

                arg_itr.next();

                let cidr = arg_itr.clone().next().unwrap().parse::<u32>().unwrap();
                args.push(IP(Ipv4Addr::from_str(ip_str).unwrap()));
                args.push(CIDR(cidr))
            }
        }
    }

    args
}

async fn sweep(config: Instance) -> ResultsSweep{
    let mut ip_map: HashMap<Ipv4Addr, Vec<u16>> = HashMap::new();

    let subnet = config.get_subnet();

    let mut hosts: Vec<Ipv4Addr> = Vec::new();

    let mut handles = Vec::new();
    let mut nets: Vec<Subnet> = Vec::new();

    let step = 8; // Lower the step, the faster but more resource intensive the program will be

    println!("Beginning sweep of {} hosts", subnet.max_hosts);

    let ping_start = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();

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
        let result = handle.await.unwrap();
        for ip in result.clone() {
            hosts.push(ip);
        }
    }

    let ping_end = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();

    println!("Ping scan finished in {:?}s, found {} alive hosts, beginning port scan of each.", (ping_end - ping_start).as_secs(), hosts.len());

    let mut handles_scan = Vec::new();

    let mut hosts_mod = hosts.clone();

    let mut host_step = subnet.clone().max_hosts / 16; // Higher the number, faster but more resource intensive program will be

    let len = hosts.len();

    let port: u32 = config.get_port();

    let mut hosts_split: Vec<Vec<Ipv4Addr>> = Vec::new();

    if host_step > len {
        host_step = len;
    }

    for _ in 0..host_step {
        hosts_split.push(hosts_mod.split_at(len / host_step).0.to_vec());
        hosts_mod = hosts_mod.split_at(len / host_step).1.to_vec();
    }

    for range in hosts_split.clone() {
        handles_scan.push(task::spawn(async move{
            sweep_net(range, Some(port)).await
        }))
    }

    for handle in handles_scan {
        let results = handle.await.unwrap();
        for result in results {
            ip_map.insert(result.ip, result.open_ports);
        }
    }

    ResultsSweep { ip_map, alive_hosts: hosts }
}

fn show_summary_sweep(results: ResultsSweep, port: Option<u32>) {
    println!("Scan results: ");
    println!("======================");
    let msg = if port.is_none() {
        "All 1000 ports closed."
    } else {
        &*("PORT    STATE       SERVICE\n".to_owned() + port.unwrap().to_string().as_str() + " \0\0\0  closed \0\0        " + PORTS.get(&(port.unwrap() as u16)).unwrap_or(&"None"))
    };
    for host in results.alive_hosts {
        println!("Scan report for {host}");
        if let Some(ports_open) = results.ip_map.get(&host) {
            if ports_open.is_empty() {
                println!("{}", msg);
            }
            for port in ports_open {
                println!("PORT      STATE       SERVICE");
                println!("{port}/tcp  open         {:?}", PORTS.get(port));
            }
        } else {
            println!("{}", msg);
        }
        println!();
    }
}

async fn resolvable(ip: Ipv4Addr, port: u32) -> Result<TcpStream, Box<dyn Error + Send + Sync>> {
    tokio::time::timeout(Duration::from_millis(600), TcpStream::connect(format!("{}:{}", ip, port)))
        .await?
        .map_err(|err| Box::new(err) as Box<dyn Error + Send + Sync>)
}

async fn get_alive_hosts(hosts: usize, ip_init: Ipv4Addr) -> Vec<Ipv4Addr> {
    let mut alive_hosts = Vec::new();

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
    pinger.timeout(Duration::from_millis(3500));

    match pinger.ping(PingSequence(0), &[ip.octets()[3]]).await {
        Ok(_) => {
            Ok(())
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

async fn sweep_net(hosts: Vec<Ipv4Addr>, port: Option<u32>) -> Vec<ResultsSingle> {
    let mut results: Vec<ResultsSingle> = Vec::new();

    for host in hosts {
        results.push(scan_ip(host, port).await);
    }

    results
}

async fn scan_ip(ip: Ipv4Addr, port: Option<u32>) -> ResultsSingle {
    let mut open_ports: Vec<u16> = Vec::new();

    if let Some(p) = port {
        if let Ok(_) = resolvable(ip, p ).await {
            return ResultsSingle { ip, open_ports: vec![p as u16] };
        }
        return ResultsSingle { ip, open_ports: Vec::new() };
    }

    for p in PORTS.keys() {
        if let Ok(_) = resolvable(ip, *p as u32).await {
            open_ports.push(*p);
        }
    }
    ResultsSingle { ip, open_ports }
}



impl Instance {
    fn build(args: Vec<String>) -> Result<Self, Box<dyn Error>> {
        if args.len() < 2 {
            return Ok(Instance { options: Vec::new() });
        }

        let options = parse_args(args);

        Ok(Instance { options })
    }

    fn get_subnet(&self) -> Subnet {

        let mut ip_start: Ipv4Addr = Ipv4Addr::LOCALHOST;

        let mut cidr = 32;

        if let IP(ip) = self.options.iter().find(|x| {
            if let IP(_) = x {
                return true;
            }
            false
        }).unwrap() {
            if let CIDR(num) = self.options.iter().find(|x1| {
                if let CIDR(_) = x1 {
                    return true;
                }
                false
            }).unwrap() {
                cidr = *num;
                ip_start = find_ip_start(*ip, *num as usize);

            }
        }

        Subnet { first_ip: ip_start, max_hosts: 2_u32.pow(32 - cidr) as usize }
    }

    fn get_port(&self) -> u32 {
        if let Port(num) = self.options.iter().find(|x| {
            if let Port(_) = x {
                return true;
            }
            false
        }).unwrap() {
            return *num;
        }


        0
    }
}