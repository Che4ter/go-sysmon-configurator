# go-sysmon-configurator
Utility to create sysmon configuration based on modules

Inspired by [sysmon-modular](https://github.com/olafhartong/sysmon-modular).
It uses the same module format but adds the follwing features:
- option to define settings like HashAlgorithm
- custom base format 
- option to remove rule name or replace with ids to minimize to log volume
- prints sha256 after generation

## Usage
- download binary
- create modules
- create base config
- for inspiration check out example/
- execute binary
```
genconfig -config=config.xml
```

**Parameters**

```-config=file.yaml``` path to base config

```-genid``` add id's to all conditions, replaces existing rule names

```-rmnames``` removes rule names


## Module Format
Each .xml module file must contain a valid sysmon config based on ruleg roups. 
At the moment modules from the sysmon-modular repository by olafhartong are compatible.

In addition the utility only includes rule groups if their event type include mode is activated in the base config file. 

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
- [ ] Sorting of conditions
- [ ] Support of multiple schemas

## Credits
- Sysinternals for providing [Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [sysmon-modular](https://github.com/olafhartong/sysmon-modular) by olafhartong for idea and many awesome modules.