## Getting Started

This is a project for implementing a payment system using javacard. This is part of the masters course for cyber security. More details about this course can be found [here](https://www.ru.nl/courseguides/science/vm/osirislinks/imc/nwi-imc066/).

To get started, clone the repo and switch to the develop branch. All changes need to be merged with the develop branch through pull requests. Changes would only be merged with the master after reaching a milestone and there is considerable stability with the codebase. PLEASE DO NOT MERGE WITH MASTER DIRECTLY.

Add the required JAR files under `Referenced Libraries` section in the document outline of vs code. 

## Folder Structure

The workspace contains two folders by default, where:

- `src`: the folder to maintain sources
- `lib`: the folder to maintain dependencies

Meanwhile, the compiled output files will be generated in the `bin` folder by default.

> If you want to customize the folder structure, open `.vscode/settings.json` and update the related settings there.

## Dependency Management

The `JAVA PROJECTS` view allows you to manage your dependencies. More details can be found [here](https://github.com/microsoft/vscode-java-dependency#manage-dependencies).
