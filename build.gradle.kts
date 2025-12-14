plugins {
    java
    idea
}

idea {
    module {
        excludeDirs.add(file("src"))
    }
}

version = "1.0.0-SNAPSHOT"