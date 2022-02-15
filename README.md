# go-sysmon-configurator
Utility to create sysmon configuration based on modules

Inspired by [sysmon-modular](https://github.com/olafhartong/sysmon-modular), but adapted to better fit my 
personal needs. 

It uses the same module format but adds the follwing features:
- option to define settings like HashAlgorithm
- customize base config 
- option to remove rule name or replace with ids to minimize to log volume
- prints sha256 after generation
- sorts condition per rulegroup based on xml tag and condition value

The configurator is not validating the schema, event types or conditions. Therefore new event types can be added to the config file without code changes.

The generated config uses a separate ```<RuleGroup>``` tag per event type an onmatch condition (include/exclude):
```
<Sysmon schemaversion="4.81">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <ProcessCreate onmatch="exclude">
      </ProcessCreate>
    </RuleGroup>
      <ProcessCreate onmatch="include">
      </ProcessCreate> 
    <RuleGroup name="" groupRelation="or">
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```

## Usage
- download binary
- define base config
- create modules
- execute binary
  
```
genconfig -config=config.xml
```
config examples are provided in /example


Install config in sysmon
```
sysmon.exe -accepteula -i sysmonconfig.xml
```

Update config in sysmon
```
sysmon.exe -c sysmonconfig.xml
```
**Parameters**

```-config=file.yaml``` path to base config

```-genid``` add id's to all conditions, replaces existing rule names

```-rmnames``` removes rule names


## Module Format
At the moment there are two module format supported. 
- The format from [sysmon-modular](https://github.com/olafhartong/sysmon-modular) repository by olafhartong which uses ```<Sysmon>``` as root tags
- The reduced format contianing only the rule using the ```<RuleGroup>``` as root tag

In addition the utility only includes rule groups if their event type include mode is activated in the base config file. 

**symon-modular format:**
```
<Sysmon schemaversion="4.81">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <ProcessCreate onmatch="exclude">
        <Image name="technique_id=T1546.011" condition="is">explorer.exe</Image>
      </ProcessCreate>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```

**reduced format:**
```
<RuleGroup name="" groupRelation="or">
  <ProcessCreate onmatch="exclude">
    <Image name="technique_id=T1546.011" condition="is">explorer.exe</Image>
  </ProcessCreate>
</RuleGroup>
```

The recommendation is to group the modules by event type in a folder structur like the following:
- modules/
  - 1_process_creation/
  - 2_file_create_time/
  - ...


## Disclaimer
The utility is currently  a working prototype and some parsing bugs are to expected. 
Therefore, review the generated sysmon configurations for errors or inconsistencies.
Currently only generated works for Sysmon 13.31 schemaversion 4.81, but the schema is not enforced.

## Feature Ideas
- [ ] Schema validation
- [ ] Schema optimizations like duplicate detection
- [x] Sorting of conditions
- [ ] Support of multiple schemas

## Credits
- Sysinternals for providing [Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [sysmon-modular](https://github.com/olafhartong/sysmon-modular) by olafhartong for idea and many awesome modules.